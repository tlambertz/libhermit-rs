// Copyright (c) 2020 Thomas Lambertz, RWTH Aachen University
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::synch::spinlock::Spinlock;
use crate::synch::std_mutex::Mutex;
use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;

/*
Design:
- want to support different backends. One of them virtiofs.
- want to support multiple mounted filesystems at once.
- for simplicity: no overlays. All 'folders' in / are mountpoints!
- manage all files in a global map. Do not hand out references, let syscalls operate by passing in closures (fd_op())

- we internally treat all file systems as posix filesystems.
- Have two traits. One representing a filesystem, another a file: PosixFileSystem and PosixFile
- filesystem.open creates new file
- trait methods like open return Result<....>, so we can catch errors on eg open() and NOT permanently assign an fd to it!

- have a FUSE filesystem, which implements both PosixFileSystem and PosixFile
- fuse can have various FuseInterface backends. These only have to provide fuse command send/receive capabilites.
- virtiofs implements FuseInterface and sends commands via virtio queues.

- fd management is only relevant for "user" facing code. We don't care how fuse etc. manages nodes internally.
- But we still want to have a list of open files and mounted filesystems (here in fs.rs).

Open Questions:
- what is the maximum number of open files I want to support? if small, could have static allocation, no need for hashmap?
- create Stdin/out virtual files, assign fd's 0-2. Instanciate them on program start. currently fd 0-2 are hardcoded exceptions.
- optimize callchain? how does LTO work here?:
	- app calls rust.open (which is stdlib hermit/fs.rs) [https://github.com/rust-lang/rust/blob/master/src/libstd/sys/hermit/fs.rs#L267]
	- abi::open() (hermit-sys crate)
	- [KERNEL BORDER] (uses C-interface. needed? Could just be alternative to native rust?)
	- hermit-lib/....rs/sys_open()
	- SyscallInterface.open (via &'static dyn ref)
	- Filesystem::open()
	- Fuse::open()
	- VirtiofsDriver::send_command(...)
	- [HYPERVISOR BORDER] (via virtio)
	- virtiofsd receives fuse command and sends reply

*/

// TODO: lazy static could be replaced with explicit init on OS boot.
pub static FILESYSTEM: VirtualFilesystem = VirtualFilesystem::new();

// Verify that VirtualFilesystem is SEND, needed cause Spinlock is unsound
#[allow(dead_code)]
static GLOBAL_WHICH_IS_SEND_AND_SYNC_1: Option<Mutex<BTreeMap<String, Box<dyn PosixFileSystem>>>> =
	None;
#[allow(dead_code)]
static GLOBAL_WHICH_IS_SEND_AND_SYNC_2: Option<Mutex<FileMap>> = None;

pub struct VirtualFilesystem {
	// Keep track of mount-points
	mounts: Spinlock<BTreeMap<String, Box<dyn PosixFileSystem>>>,

	// Keep track of open files
	files: Spinlock<FileMap>,
}

type LockableFile = Arc<Mutex<Box<dyn PosixFile>>>;
type FileDescriptor = u64;
struct FileMap {
	files: BTreeMap<FileDescriptor, LockableFile>,
}

impl FileMap {
	pub const fn new() -> Self {
		Self {
			files: BTreeMap::new(),
		}
	}

	/// Returns next free file-descriptor. We map index in files BTreeMap as fd's.
	/// Done determining the current biggest stored index.
	/// This is efficient, since BTreeMap's iter() calculates min and max key directly.
	/// see https://github.com/rust-lang/rust/issues/62924
	fn assign_new_fd(&self) -> FileDescriptor {
		// BTreeMap has efficient max/min index calculation. One way to access these is the following iter.
		// Add 1 to get next never-assigned fd num
		if let Some((fd, _)) = self.files.iter().next_back() {
			fd + 1
		} else {
			3 // start at 3, to reserve stdin/out/err
		}
	}

	/// Given a file, it allocates a file descriptor and inserts it into map of open files.
	/// Returns file descriptor
	pub fn add_file(&mut self, file: Box<dyn PosixFile>) -> FileDescriptor {
		let fd = self.assign_new_fd();
		self.files.insert(fd, Arc::new(Mutex::new(file)));
		fd
	}

	/// Returns a file. Cloned.
	pub fn get_file(&mut self, fd: FileDescriptor) -> Option<LockableFile> {
		self.files.get_mut(&fd).map(|x| x.clone())
	}

	/// Removes the file from the map, returning it if present
	pub fn remove(&mut self, fd: FileDescriptor) -> Option<LockableFile> {
		self.files.remove(&fd)
	}
}

/// parses path `/MOUNTPOINT/internal-path` into mount-filesystem and internal_path
/// Returns (MOUNTPOINT, internal_path) or Error on failure.
fn parse_path(path: &str) -> Result<(&str, &str), FileError> {
	// assert start with / (no pwd relative!), split path at /, look first element. Determine backing fs. If non existent, -ENOENT
	if !path.starts_with('/') {
		warn!("Relative paths not allowed!");
		return Err(FileError::ENOENT);
	}
	let mut pathsplit = path.splitn(3, '/');
	pathsplit.next(); // always empty, since first char is /
	let mount = pathsplit.next().unwrap();
	let internal_path = pathsplit.next().unwrap(); //TODO: this can fail from userspace, eg when passing "/test"

	Ok((mount, internal_path))
}

impl VirtualFilesystem {
	pub const fn new() -> Self {
		Self {
			mounts: Spinlock::new(BTreeMap::new()),
			files: Spinlock::new(FileMap::new()),
		}
	}

	/// Tries to open file at given path (/MOUNTPOINT/internal-path).
	/// Looks up MOUNTPOINT in mounted dirs, passes internal-path to filesystem backend
	/// Returns the file descriptor of the newly opened file, or an error on failure
	pub fn open(&self, path: &str, perms: FilePerms) -> Result<FileDescriptor, FileError> {
		debug!("Opening file {} {:?}", path, perms);
		let (mountpoint, internal_path) = parse_path(path)?;

		if let Some(fs) = self.mounts.lock().get(mountpoint) {
			let file = fs.open(internal_path, perms)?;
			Ok(self.files.lock().add_file(file))
		} else {
			info!(
				"Trying to open file on non-existing mount point '{}'!",
				mountpoint
			);
			Err(FileError::ENOENT)
		}
	}

	pub fn close(&self, fd: FileDescriptor) {
		debug!("Closing fd {}", fd);

		// Remove file from map, so nobody else can access it anymore
		// If it exists, close it

		let file = self.files.lock().remove(fd);
		if let Some(file) = file {
			// Lock the file, so we are only ones with access
			let mut file = file.lock();
			file.close().unwrap(); // TODO: handle error

			// File is unlocked again, so other pending operations can happen (fail)
		}
	}

	/// Unlinks a file given by path
	pub fn unlink(&self, path: &str) -> Result<(), FileError> {
		debug!("Unlinking file {}", path);
		let (mountpoint, internal_path) = parse_path(path)?;

		// TODO: deduplicate this mount parsing/locking/error code with other functions
		if let Some(fs) = self.mounts.lock().get(mountpoint) {
			fs.unlink(internal_path)?;
			Ok(())
		} else {
			info!(
				"Trying to unlink file on non-existing mount point '{}'!",
				mountpoint
			);
			Err(FileError::ENOENT)
		}
	}

	/// Stats a file given by path
	pub fn stat(&self, path: &str) -> Result<Stat, FileError> {
		debug!("Stat file {}", path);
		let (mountpoint, internal_path) = parse_path(path)?;

		// TODO: deduplicate this mount parsing/locking/error code with other functions
		if let Some(fs) = self.mounts.lock().get(mountpoint) {
			Ok(fs.stat(internal_path)?)
		} else {
			info!(
				"Trying to unlink file on non-existing mount point '{}'!",
				mountpoint
			);
			Err(FileError::ENOENT)
		}
	}

	/// Create new backing-fs at mountpoint mntpath
	pub fn mount(&self, mntpath: &str, mntobj: Box<dyn PosixFileSystem>) -> Result<(), ()> {
		info!("Mounting {}", mntpath);
		if mntpath.contains('/') {
			warn!(
				"Trying to mount at '{}', but slashes in name are not supported!",
				mntpath
			);
			return Err(());
		}

		// if mounts contains path already abort
		if self.mounts.lock().contains_key(mntpath) {
			warn!("Mountpoint already exists!");
			return Err(());
		}

		// insert filesystem into mounts, done
		self.mounts.lock().insert(mntpath.to_owned(), mntobj);
		Ok(())
	}

	pub fn read(&self, fd: FileDescriptor, buf: &mut [u8]) -> Result<usize, FileError> {
		let file = self.files.lock().get_file(fd);
		if let Some(file) = file {
			// Get exclusive access to file and write
			file.lock().read(buf)
		} else {
			// File does not exist!
			Err(FileError::ENOENT)
		}
	}

	pub fn write(&self, fd: FileDescriptor, buf: &[u8]) -> Result<usize, FileError> {
		let file = self.files.lock().get_file(fd);
		if let Some(file) = file {
			// Get exclusive access to file and write
			file.lock().write(buf)
		} else {
			// File does not exist!
			Err(FileError::ENOENT)
		}
	}

	pub fn lseek(
		&self,
		fd: FileDescriptor,
		offset: isize,
		whence: SeekWhence,
	) -> Result<usize, FileError> {
		let file = self.files.lock().get_file(fd);
		if let Some(file) = file {
			// Get exclusive access to file and write
			file.lock().lseek(offset, whence)
		} else {
			// File does not exist!
			Err(FileError::ENOENT)
		}
	}

	pub fn fsync(&self, fd: FileDescriptor) -> Result<(), FileError> {
		let file = self.files.lock().get_file(fd);
		if let Some(file) = file {
			// Get exclusive access to file and write
			file.lock().fsync()
		} else {
			// File does not exist!
			Err(FileError::ENOENT)
		}
	}

	/// Run closure on file referenced by file descriptor.
	pub fn fd_op(&self, fd: FileDescriptor, f: impl FnOnce(Option<&mut Box<dyn PosixFile>>)) {
		let file = self.files.lock().get_file(fd);
		if let Some(file) = file {
			// Get exclusive access to file
			let mut file = file.lock();

			// Do operation
			f(Some(&mut file));
		} else {
			// File does not exist!
			f(None);
		}
	}
}

#[derive(Debug)]
pub enum FileError {
	ENOENT,
	ENOSYS,
	EIO,
}

pub trait PosixFileSystem: Send {
	fn open(&self, _path: &str, _perms: FilePerms) -> Result<Box<dyn PosixFile>, FileError>;
	fn unlink(&self, _path: &str) -> Result<(), FileError>;
	fn stat(&self, path: &str) -> Result<Stat, FileError>;
}

pub trait PosixFile: Send {
	fn close(&mut self) -> Result<(), FileError>;
	fn read(&mut self, buf: &mut [u8]) -> Result<usize, FileError>;
	fn write(&mut self, buf: &[u8]) -> Result<usize, FileError>;
	fn lseek(&mut self, offset: isize, whence: SeekWhence) -> Result<usize, FileError>;

	fn fsync(&mut self) -> Result<(), FileError> {
		info!("fsync is unimplemented");
		Err(FileError::ENOSYS)
	}
}

/// File stat. Currently 1:1 fuse stats
#[derive(Clone, Copy, Debug, Default)]
pub struct Stat {
	pub ino: u64,
	pub size: u64,
	pub blocks: u64,
	pub atime: u64,
	pub mtime: u64,
	pub ctime: u64,
	pub atimensec: u32,
	pub mtimensec: u32,
	pub ctimensec: u32,
	pub mode: u32, // eg 0o100644
	pub nlink: u32,
	pub uid: u32,
	pub gid: u32,
	pub rdev: u32,
	pub blksize: u32,
	pub padding: u32,
}

// TODO: raw is partially redundant, create nicer interface
#[derive(Clone, Copy, Debug, Default)]
pub struct FilePerms {
	pub write: bool,
	pub creat: bool,
	pub excl: bool,
	pub trunc: bool,
	pub append: bool,
	pub directio: bool,
	pub raw: u32,
	pub mode: u32,
}

pub enum SeekWhence {
	Set,
	Cur,
	End,
}
