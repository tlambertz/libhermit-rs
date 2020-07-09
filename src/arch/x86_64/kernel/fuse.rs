// Copyright (c) 2020 Thomas Lambertz, RWTH Aachen University
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use super::fuse_dax::{CacheEntry, DaxAllocator, FuseDaxCache, FUSE_DAX_MEM_RANGE_SZ};
use crate::syscalls::fs::{FileError, FilePerms, PosixFile, PosixFileSystem, SeekWhence};
use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::{fmt, u32, u8};

// response out layout eg @ https://github.com/zargony/fuse-rs/blob/bf6d1cf03f3277e35b580f3c7b9999255d72ecf3/src/ll/request.rs#L44
// op in/out sizes/layout: https://github.com/hanwen/go-fuse/blob/204b45dba899dfa147235c255908236d5fde2d32/fuse/opcode.go#L439
// possible reponses for command: qemu/tools/virtiofsd/fuse_lowlevel.h

const FUSE_ROOT_ID: u64 = 1;
const MAX_READ_LEN: usize = 1024 * 64;
const MAX_WRITE_LEN: usize = 1024 * 64;

pub trait FuseInterface {
	fn send_command<S, T>(&mut self, cmd: Cmd<S>, rsp: Option<Rsp<T>>) -> Option<Rsp<T>>
	where
		S: FuseIn + core::fmt::Debug,
		T: FuseOut + core::fmt::Debug;
}

pub struct Fuse<T: FuseInterface> {
	driver: Rc<RefCell<T>>,
	dax_allocator: Option<Rc<RefCell<DaxAllocator>>>,
}

impl<T: FuseInterface + 'static> PosixFileSystem for Fuse<T> {
	fn open(&self, path: &str, perms: FilePerms) -> Result<Box<dyn PosixFile>, FileError> {
		// 1.FUSE_INIT to create session
		// Already done
		let fuse_nid;
		let fuse_fh;
		let fuse_attr;

		// Differentiate between opening and creating new file, since fuse does not support O_CREAT on open.
		if !perms.creat {
			// 2.FUSE_LOOKUP(FUSE_ROOT_ID, “foo”) -> nodeid
			let entry = self.lookup(path);

			if let Some(entry) = entry {
				fuse_nid = entry.nodeid;
				fuse_attr = entry.attr;
			} else {
				warn!("Fuse lookup seems to have failed!");
				return Err(FileError::ENOENT());
			}
			// 3.FUSE_OPEN(nodeid, O_RDONLY) -> fh
			let (cmd, rsp) = create_open(fuse_nid, perms.raw);
			let rsp = self.driver.borrow_mut().send_command(cmd, Some(rsp));
			trace!("Open answer {:?}", rsp);
			fuse_fh = Some(rsp.unwrap().rsp.fh);
		} else {
			// Create file (opens implicitly, returns results from both lookup and open calls)
			let (cmd, rsp) = create_create(path, perms.raw, perms.mode);
			let rsp = self
				.driver
				.borrow_mut()
				.send_command(cmd, Some(rsp))
				.unwrap();
			trace!("Create answer {:?}", rsp);

			fuse_nid = rsp.rsp.entry.nodeid;
			fuse_fh = Some(rsp.rsp.open.fh);
			fuse_attr = rsp.rsp.entry.attr;
		}

		let file = FuseFile {
			driver: self.driver.clone(),
			fuse_nid: Some(fuse_nid),
			fuse_fh,
			offset: 0,
			dax_cache: self
				.dax_allocator
				.as_ref()
				.map(|a| FuseDaxCache::new(a.clone())),
			attr: fuse_attr,
			open_options: perms,
		};
		Ok(Box::new(file))
	}

	fn unlink(&self, path: &str) -> core::result::Result<(), FileError> {
		let (cmd, rsp) = create_unlink(path);
		let rsp = self.driver.borrow_mut().send_command(cmd, Some(rsp));
		trace!("unlink answer {:?}", rsp);

		Ok(())
	}
}

impl<T: FuseInterface + 'static> Fuse<T> {
	pub fn new(driver: Rc<RefCell<T>>) -> Self {
		Self {
			driver,
			dax_allocator: None,
		}
	}

	pub fn new_with_dax(driver: Rc<RefCell<T>>, dax_allocator: DaxAllocator) -> Self {
		Self {
			driver,
			dax_allocator: Some(Rc::new(RefCell::new(dax_allocator))),
		}
	}

	pub fn send_init(&self) {
		let (cmd, rsp) = create_init();
		let rsp = self.driver.borrow_mut().send_command(cmd, Some(rsp));
		trace!("fuse init answer: {:?}", rsp);
	}

	pub fn lookup(&self, name: &str) -> Option<fuse_entry_out> {
		let (cmd, rsp) = create_lookup(name);
		let rsp = self.driver.borrow_mut().send_command(cmd, Some(rsp));
		Some(rsp.unwrap().rsp)
	}
}

struct FuseFile<T: FuseInterface> {
	driver: Rc<RefCell<T>>,
	fuse_nid: Option<u64>,
	fuse_fh: Option<u64>,
	offset: usize,
	dax_cache: Option<FuseDaxCache>,
	attr: fuse_attr,
	open_options: FilePerms,
}

impl<T: FuseInterface> FuseFile<T> {
	/// Reads the file using normal fuse read commands. File contents are in fuse reply
	fn read_fuse(&mut self, len: u32) -> Result<Vec<u8>, FileError> {
		let mut len = len;
		if len as usize > MAX_READ_LEN {
			debug!("Reading longer than max_read_len: {}", len);
			len = MAX_READ_LEN as u32;
		}
		if let Some(fh) = self.fuse_fh {
			let (cmd, rsp) = create_read(fh, len, self.offset as u64);
			let rsp = self.driver.borrow_mut().send_command(cmd, Some(rsp));
			let rsp = rsp.unwrap();
			let len = rsp.header.len as usize - ::core::mem::size_of::<fuse_out_header>();
			self.offset += len;
			// TODO: do this zerocopy
			let mut vec = rsp.extra_buffer.unwrap();
			vec.truncate(len);
			trace!("LEN: {}, VEC: {:?}", len, vec);
			Ok(vec)
		} else {
			warn!("File not open, cannot read!");
			Err(FileError::ENOENT())
		}
	}

	/// Uses fuse setupmapping to create a DAX mapping, and copies from that. Mappings are cached
	fn read_dax(&mut self, len: u32) -> Result<Vec<u8>, FileError> {
		trace!("read_dax({:x}) from offset {:x}", len, self.offset);
		let mut cached = self.get_cached()?.clone();
		let cached = cached.as_buf(self.offset as u64);

		// Limit read length to buffer boundary
		let mut len = len as usize;
		if cached.len() < len {
			len = cached.len();
		}

		// Limit length to file size
		if self.offset + len > self.attr.size as usize {
			trace!(
				"Limiting file read over EOF: {}, {}, {}",
				self.offset,
				len,
				self.attr.size
			);
			len = self.attr.size as usize - self.offset;
		}

		self.offset += len;

		// Copy buffer into output.
		// TODO: zerocopy?
		let mut vec = cached[..len].to_vec();
		vec.truncate(len);
		trace!("read_dax output: {:?}", vec);
		Ok(vec)
	}

	fn write_fuse(&mut self, buf: &[u8]) -> Result<u64, FileError> {
		let mut len = buf.len();
		if len as usize > MAX_WRITE_LEN {
			debug!(
				"Writing longer than max_write_len: {} > {}",
				buf.len(),
				MAX_WRITE_LEN
			);
			len = MAX_WRITE_LEN;
		}
		if let Some(fh) = self.fuse_fh {
			let (cmd, rsp) = create_write(fh, &buf[..len], self.offset as u64);
			let rsp = self.driver.borrow_mut().send_command(cmd, Some(rsp));
			trace!("write response: {:?}", rsp);
			let rsp = rsp.unwrap();

			let len = rsp.rsp.size as usize;
			self.offset += len;

			// Update file size if needed
			if self.offset > self.attr.size as usize {
				trace!(
					"File-extending write, updating size!: {}, {}, {}",
					self.offset,
					len,
					self.attr.size
				);
				self.attr.size = self.offset as u64;
			}
			debug!("Written {} bytes", len);
			Ok(len as u64)
		} else {
			warn!("File not open, cannot read!");
			Err(FileError::ENOENT())
		}
	}

	fn write_dax(&mut self, buf: &[u8]) -> Result<u64, FileError> {
		let mut len = buf.len() as usize;

		trace!("write_dax({:x}) from offset {:x}", len, self.offset);

		// If write is file-extending, fall back to write_fuse()
		if self.offset + len > self.attr.size as usize {
			trace!(
				"File-extending write, fallback to fuse write: {}, {}, {}",
				self.offset,
				len,
				self.attr.size
			);
			return self.write_fuse(buf);
		}

		let mut cached = self.get_cached()?.clone();
		let cached = cached.as_buf(self.offset as u64);

		// Limit write length to buffer boundary
		if cached.len() < len {
			len = cached.len();
		}

		self.offset += len;

		// Write buffer into cache.
		cached[..len].copy_from_slice(buf);

		Ok(len as u64)
	}

	/// Returns true if the file is opened with write flag and anyone (owner/group/public) has write permissions
	fn writable(&self) -> bool {
		self.open_options.write && self.attr.mode & 0o222 > 0
	}

	fn get_cached(&mut self) -> Result<CacheEntry, FileError> {
		let cache = self.dax_cache.as_mut().unwrap();
		if let Some(entry) = cache.get_cached(self.offset as u64) {
			// Offset is already mapped, fast path!
			trace!("Already cached dax, fast path. {:?}", entry);
			return Ok(entry);
		}

		// Offset is not yet mapped, do it now!
		let entry = cache
			.alloc_cache(self.offset as u64)
			.expect("Could not alloc DAX cache"); // TODO: free cache entry, try again
		if let Some(fh) = self.fuse_fh {
			let mut flags = FUSE_SETUPMAPPING_FLAG_READ;
			if self.writable() {
				flags |= FUSE_SETUPMAPPING_FLAG_WRITE;
			}
			let (cmd, rsp) = create_setupmapping(
				fh,
				self.offset as u64,
				FUSE_DAX_MEM_RANGE_SZ as u64,
				flags,
				entry.get_moffset(),
			);
			let rsp = self.driver.borrow_mut().send_command(cmd, Some(rsp));
			// TODO: check for errors. mapping might have failed.
			Ok(entry)
		} else {
			warn!("File not open, cannot read_dax!");
			Err(FileError::ENOENT())
		}
	}

	/// Drops all DAX mappings
	fn drop_cache(&mut self) {
		if let Some(cache) = &mut self.dax_cache {
			// moffset = 0 and length = 0 --> Remove all mappings
			let (cmd, rsp) = create_removemapping(self.fuse_nid.unwrap_or(0), 0, 0);
			let rsp = self.driver.borrow_mut().send_command(cmd, Some(rsp));

			cache.free();
		}
	}
}

impl<T: FuseInterface> PosixFile for FuseFile<T> {
	fn close(&mut self) -> Result<(), FileError> {
		self.drop_cache();
		let (cmd, rsp) = create_release(self.fuse_nid.unwrap(), self.fuse_fh.unwrap());
		self.driver.borrow_mut().send_command(cmd, Some(rsp));

		Ok(())
	}

	fn read(&mut self, len: u32) -> Result<Vec<u8>, FileError> {
		if self.dax_cache.is_some() {
			self.read_dax(len)
		} else {
			self.read_fuse(len)
		}
	}

	fn write(&mut self, buf: &[u8]) -> Result<u64, FileError> {
		debug!("fuse write!");
		if self.dax_cache.is_some() {
			self.write_dax(buf)
		} else {
			self.write_fuse(buf)
		}
	}

	fn lseek(&mut self, offset: isize, whence: SeekWhence) -> Result<usize, FileError> {
		debug!("fuse lseek");

		match whence {
			SeekWhence::Set => self.offset = offset as usize,
			SeekWhence::Cur => self.offset = (self.offset as isize + offset) as usize,
			SeekWhence::End => unimplemented!("Cant seek from end yet!"),
		}

		Ok(self.offset)
	}
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[allow(non_camel_case_types)]
pub enum Opcode {
	FUSE_LOOKUP = 1,
	FUSE_FORGET = 2, // no reply
	FUSE_GETATTR = 3,
	FUSE_SETATTR = 4,
	FUSE_READLINK = 5,
	FUSE_SYMLINK = 6,
	FUSE_MKNOD = 8,
	FUSE_MKDIR = 9,
	FUSE_UNLINK = 10,
	FUSE_RMDIR = 11,
	FUSE_RENAME = 12,
	FUSE_LINK = 13,
	FUSE_OPEN = 14,
	FUSE_READ = 15,
	FUSE_WRITE = 16,
	FUSE_STATFS = 17,
	FUSE_RELEASE = 18,
	FUSE_FSYNC = 20,
	FUSE_SETXATTR = 21,
	FUSE_GETXATTR = 22,
	FUSE_LISTXATTR = 23,
	FUSE_REMOVEXATTR = 24,
	FUSE_FLUSH = 25,
	FUSE_INIT = 26,
	FUSE_OPENDIR = 27,
	FUSE_READDIR = 28,
	FUSE_RELEASEDIR = 29,
	FUSE_FSYNCDIR = 30,
	FUSE_GETLK = 31,
	FUSE_SETLK = 32,
	FUSE_SETLKW = 33,
	FUSE_ACCESS = 34,
	FUSE_CREATE = 35,
	FUSE_INTERRUPT = 36,
	FUSE_BMAP = 37,
	FUSE_DESTROY = 38,
	FUSE_IOCTL = 39,
	FUSE_POLL = 40,
	FUSE_NOTIFY_REPLY = 41,
	FUSE_BATCH_FORGET = 42,
	FUSE_FALLOCATE = 43,

	FUSE_SETUPMAPPING = 48,
	FUSE_REMOVEMAPPING = 49,

	FUSE_SETVOLNAME = 61,
	FUSE_GETXTIMES = 62,
	FUSE_EXCHANGE = 63,

	CUSE_INIT = 4096,
}

// From https://stackoverflow.com/questions/28127165/how-to-convert-struct-to-u8
/*unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
	::core::slice::from_raw_parts(
		(p as *const T) as *const u8,
		::core::mem::size_of::<T>(),
	)
}
unsafe fn any_as_u8_slice_mut<T: Sized>(p: &mut T) -> &mut [u8] {
	::core::slice::from_raw_parts_mut(
		(p as *mut T) as *mut u8,
		::core::mem::size_of::<T>(),
	)
}*/

/// Marker trait, which signals that a struct is a valid Fuse command.
/// Struct has to be repr(C)!
pub unsafe trait FuseIn {}
/// Marker trait, which signals that a struct is a valid Fuse response.
/// Struct has to be repr(C)!
pub unsafe trait FuseOut {}

#[repr(C)]
#[derive(Debug)]
pub struct Cmd<T: FuseIn + core::fmt::Debug> {
	header: fuse_in_header,
	cmd: T,
	extra_buffer: Option<Vec<u8>>, // eg for writes. allows zero-copy and avoids rust size_of operations (which always add alignment padding)
}

#[repr(C)]
#[derive(Debug)]
pub struct Rsp<T: FuseOut + core::fmt::Debug> {
	header: fuse_out_header,
	rsp: T,
	extra_buffer: Option<Vec<u8>>, // eg for reads. allows zero-copy and avoids rust size_of operations (which always add alignment padding)
}

// TODO: use from/into? But these require consuming the command, so we need some better memory model to avoid deallocation
impl<T> Cmd<T>
where
	T: FuseIn + core::fmt::Debug,
{
	pub fn to_u8buf(&self) -> Vec<&[u8]> {
		let rawcmd = unsafe {
			::core::slice::from_raw_parts(
				(&self.header as *const fuse_in_header) as *const u8,
				::core::mem::size_of::<T>() + ::core::mem::size_of::<fuse_in_header>(),
			)
		};
		if let Some(extra) = &self.extra_buffer {
			vec![rawcmd, &extra.as_ref()]
		} else {
			vec![rawcmd]
		}
	}
}
impl<T> Rsp<T>
where
	T: FuseOut + core::fmt::Debug,
{
	pub fn to_u8buf_mut(&mut self) -> Vec<&mut [u8]> {
		let rawrsp = unsafe {
			::core::slice::from_raw_parts_mut(
				(&mut self.header as *mut fuse_out_header) as *mut u8,
				::core::mem::size_of::<T>() + ::core::mem::size_of::<fuse_out_header>(),
			)
		};
		if let Some(extra) = self.extra_buffer.as_mut() {
			vec![rawrsp, extra]
		} else {
			vec![rawrsp]
		}
	}
}

pub fn create_in_header<T>(opcode: Opcode) -> fuse_in_header
where
	T: FuseIn,
{
	fuse_in_header {
		len: (core::mem::size_of::<T>() + core::mem::size_of::<T>()) as u32,
		opcode: opcode as u32,
		unique: 1,
		nodeid: 0,
		uid: 0,
		pid: 0,
		gid: 0,
		padding: 0,
	}
}

pub fn create_init() -> (Cmd<fuse_init_in>, Rsp<fuse_init_out>) {
	let cmd = fuse_init_in {
		major: 7,
		minor: 31,
		max_readahead: 0,
		flags: 0,
	};
	let cmdhdr = create_in_header::<fuse_init_in>(Opcode::FUSE_INIT);
	let rsp: fuse_init_out = Default::default();
	let rsphdr: fuse_out_header = Default::default();
	(
		Cmd {
			cmd,
			header: cmdhdr,
			extra_buffer: None,
		},
		Rsp {
			rsp,
			header: rsphdr,
			extra_buffer: None,
		},
	)
}

pub fn create_lookup(name: &str) -> (Cmd<fuse_lookup_in>, Rsp<fuse_entry_out>) {
	let cmd = name.into();
	let mut cmdhdr = create_in_header::<fuse_lookup_in>(Opcode::FUSE_LOOKUP);
	cmdhdr.nodeid = FUSE_ROOT_ID;
	let rsp: fuse_entry_out = Default::default();
	let rsphdr: fuse_out_header = Default::default();
	(
		Cmd {
			cmd,
			header: cmdhdr,
			extra_buffer: None,
		},
		Rsp {
			rsp,
			header: rsphdr,
			extra_buffer: None,
		},
	)
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_in_header {
	pub len: u32,
	pub opcode: u32,
	pub unique: u64,
	pub nodeid: u64,
	pub uid: u32,
	pub gid: u32,
	pub pid: u32,
	pub padding: u32,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct fuse_out_header {
	pub len: u32,
	pub error: i32,
	pub unique: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_init_in {
	pub major: u32,
	pub minor: u32,
	pub max_readahead: u32,
	pub flags: u32,
}
unsafe impl FuseIn for fuse_init_in {}

#[repr(C)]
#[derive(Debug, Default)]
pub struct fuse_init_out {
	pub major: u32,
	pub minor: u32,
	pub max_readahead: u32,
	pub flags: u32,
	pub max_background: u16,
	pub congestion_threshold: u16,
	pub max_write: u32,
	pub time_gran: u32,
	pub unused: [u32; 9],
}
unsafe impl FuseOut for fuse_init_out {}

#[repr(C)]
#[derive(Default, Debug)]
pub struct fuse_read_in {
	pub fh: u64,
	pub offset: u64,
	pub size: u32,
	pub read_flags: u32,
	pub lock_owner: u64,
	pub flags: u32,
	pub padding: u32,
}
unsafe impl FuseIn for fuse_read_in {}

#[repr(C)]
#[derive(Default, Debug)]
pub struct fuse_read_out {}
unsafe impl FuseOut for fuse_read_out {}

pub fn create_read(nid: u64, size: u32, offset: u64) -> (Cmd<fuse_read_in>, Rsp<fuse_read_out>) {
	let cmd = fuse_read_in {
		offset,
		size,
		..Default::default()
	};
	let mut cmdhdr = create_in_header::<fuse_read_in>(Opcode::FUSE_READ);
	cmdhdr.nodeid = nid;
	let rsp = Default::default();
	let rsphdr = Default::default();
	// direct-io requires aligned memory.
	// ugly hack from https://stackoverflow.com/questions/60180121/how-do-i-allocate-a-vecu8-that-is-aligned-to-the-size-of-the-cache-line
	let mut aligned: Vec<AlignToPage> =
		Vec::with_capacity(size as usize / ::core::mem::size_of::<AlignToPage>() + 1);
	let ptr = aligned.as_mut_ptr();
	let cap_units = aligned.capacity();
	::core::mem::forget(aligned);
	let readbuf = unsafe {
		Vec::from_raw_parts(
			ptr as *mut u8,
			size as usize,
			cap_units * ::core::mem::size_of::<AlignToPage>(),
		)
	};
	// let readbuf = vec![0; size as usize];
	(
		Cmd {
			cmd,
			header: cmdhdr,
			extra_buffer: None,
		},
		Rsp {
			rsp,
			header: rsphdr,
			extra_buffer: Some(readbuf),
		},
	)
}

#[repr(C)]
#[derive(Default, Debug)]
pub struct fuse_write_in {
	pub fh: u64,
	pub offset: u64,
	pub size: u32,
	pub write_flags: u32,
	pub lock_owner: u64,
	pub flags: u32,
	pub padding: u32,
}
unsafe impl FuseIn for fuse_write_in {}

#[repr(C)]
#[derive(Default, Debug)]
pub struct fuse_write_out {
	pub size: u32,
	pub padding: u32,
}
unsafe impl FuseOut for fuse_write_out {}

#[repr(C, align(4096))]
struct AlignToPage([u8; 4096]);
// TODO: do write zerocopy? currently does buf.to_vec()
// problem: i cannot create owned type, since this would deallocate memory on drop. But memory belongs to userspace!
//          Using references, i have to be careful of lifetimes!
pub fn create_write(
	nid: u64,
	buf: &[u8],
	offset: u64,
) -> (Cmd<fuse_write_in>, Rsp<fuse_write_out>) {
	let cmd = fuse_write_in {
		offset,
		size: buf.len() as u32,
		..Default::default()
	};
	let mut cmdhdr = create_in_header::<fuse_write_in>(Opcode::FUSE_WRITE);
	cmdhdr.nodeid = nid;
	let rsp = Default::default();
	let rsphdr = Default::default();

	//direct-io requires aligned memory.
	// ugly hack from https://stackoverflow.com/questions/60180121/how-do-i-allocate-a-vecu8-that-is-aligned-to-the-size-of-the-cache-line
	let mut aligned: Vec<AlignToPage> =
		Vec::with_capacity(buf.len() / ::core::mem::size_of::<AlignToPage>() + 1);
	let ptr = aligned.as_mut_ptr();
	let cap_units = aligned.capacity();
	::core::mem::forget(aligned);
	let mut writebuf = unsafe {
		Vec::from_raw_parts(
			ptr as *mut u8,
			buf.len(),
			cap_units * ::core::mem::size_of::<AlignToPage>(),
		)
	};
	writebuf.clone_from_slice(buf);
	// let writebuf = buf.to_vec();
	(
		Cmd {
			cmd,
			header: cmdhdr,
			extra_buffer: Some(writebuf),
		},
		Rsp {
			rsp,
			header: rsphdr,
			extra_buffer: None,
		},
	)
}

#[repr(C)]
#[derive(Default, Debug)]
pub struct fuse_open_in {
	pub flags: u32,
	pub unused: u32,
}
unsafe impl FuseIn for fuse_open_in {}

#[repr(C)]
#[derive(Default, Debug)]
pub struct fuse_open_out {
	pub fh: u64,
	pub open_flags: u32,
	pub padding: u32,
}
unsafe impl FuseOut for fuse_open_out {}

pub fn create_open(nid: u64, flags: u32) -> (Cmd<fuse_open_in>, Rsp<fuse_open_out>) {
	let cmd = fuse_open_in {
		flags,
		..Default::default()
	};
	let mut cmdhdr = create_in_header::<fuse_open_in>(Opcode::FUSE_OPEN);
	cmdhdr.nodeid = nid;
	let rsp = Default::default();
	let rsphdr = Default::default();
	(
		Cmd {
			cmd,
			header: cmdhdr,
			extra_buffer: None,
		},
		Rsp {
			rsp,
			header: rsphdr,
			extra_buffer: None,
		},
	)
}

#[repr(C)]
#[derive(Default, Debug)]
pub struct fuse_release_in {
	pub fh: u64,
	pub flags: u32,
	pub release_flags: u32,
	pub lock_owner: u64,
}
unsafe impl FuseIn for fuse_release_in {}

#[repr(C)]
#[derive(Default, Debug)]
pub struct fuse_release_out {}
unsafe impl FuseOut for fuse_release_out {}

pub fn create_release(nid: u64, fh: u64) -> (Cmd<fuse_release_in>, Rsp<fuse_release_out>) {
	let mut cmd: fuse_release_in = Default::default();
	let mut cmdhdr = create_in_header::<fuse_release_in>(Opcode::FUSE_RELEASE);
	cmdhdr.nodeid = nid;
	cmd.fh = fh;
	let rsp = Default::default();
	let rsphdr = Default::default();
	(
		Cmd {
			cmd,
			header: cmdhdr,
			extra_buffer: None,
		},
		Rsp {
			rsp,
			header: rsphdr,
			extra_buffer: None,
		},
	)
}

fn str_into_u8buf(s: &str, u8buf: &mut [u8]) {
	// TODO: fix this hacky conversion..
	for (i, c) in s.chars().enumerate() {
		u8buf[i] = c as u8;
		if i > u8buf.len() {
			warn!("FUSE: Name too long!");
			break;
		}
	}
}

// TODO: max path length?
const MAX_PATH_LEN: usize = 256;
fn str_to_path(s: &str) -> [u8; MAX_PATH_LEN] {
	let mut buf = [0 as u8; MAX_PATH_LEN];
	str_into_u8buf(s, &mut buf);
	buf
}

#[repr(C)]
pub struct fuse_lookup_in {
	pub name: [u8; MAX_PATH_LEN],
}
unsafe impl FuseIn for fuse_lookup_in {}

impl From<&str> for fuse_lookup_in {
	fn from(name: &str) -> Self {
		Self {
			name: str_to_path(name),
		}
	}
}

impl fmt::Debug for fuse_lookup_in {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "fuse_lookup_in {{ {:?} }}", &self.name[..])
	}
}

#[repr(C)]
#[derive(Default, Debug)]
pub struct fuse_entry_out {
	pub nodeid: u64,
	pub generation: u64,
	pub entry_valid: u64,
	pub attr_valid: u64,
	pub entry_valid_nsec: u32,
	pub attr_valid_nsec: u32,
	pub attr: fuse_attr,
}
unsafe impl FuseOut for fuse_entry_out {}

#[repr(C)]
#[derive(Default, Debug)]
pub struct fuse_attr {
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

#[repr(C)]
pub struct fuse_unlink_in {
	pub name: [u8; MAX_PATH_LEN],
}
unsafe impl FuseIn for fuse_unlink_in {}

impl From<&str> for fuse_unlink_in {
	fn from(name: &str) -> Self {
		Self {
			name: str_to_path(name),
		}
	}
}

impl fmt::Debug for fuse_unlink_in {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "fuse_unlink_in {{ {:?} }}", &self.name[..])
	}
}

#[repr(C)]
#[derive(Default, Debug)]
pub struct fuse_unlink_out {}
unsafe impl FuseOut for fuse_unlink_out {}

pub fn create_unlink(name: &str) -> (Cmd<fuse_unlink_in>, Rsp<fuse_unlink_out>) {
	let cmd = name.into();
	let mut cmdhdr = create_in_header::<fuse_unlink_in>(Opcode::FUSE_UNLINK);
	cmdhdr.nodeid = FUSE_ROOT_ID;
	let rsp: fuse_unlink_out = Default::default();
	let rsphdr: fuse_out_header = Default::default();
	(
		Cmd {
			cmd,
			header: cmdhdr,
			extra_buffer: None,
		},
		Rsp {
			rsp,
			header: rsphdr,
			extra_buffer: None,
		},
	)
}

#[repr(C)]
pub struct fuse_create_in {
	pub flags: u32,
	pub mode: u32,
	pub umask: u32,
	pub padding: u32,
	pub name: [u8; MAX_PATH_LEN],
}
unsafe impl FuseIn for fuse_create_in {}

#[repr(C)]
#[derive(Debug, Default)]
pub struct fuse_create_out {
	pub entry: fuse_entry_out,
	pub open: fuse_open_out,
}
unsafe impl FuseOut for fuse_create_out {}

impl fuse_create_in {
	fn new(name: &str, flags: u32, mode: u32) -> Self {
		Self {
			flags,
			mode,
			umask: 0,
			padding: 0,
			name: str_to_path(name),
		}
	}
}

impl fmt::Debug for fuse_create_in {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(
			f,
			"fuse_create_in {{ flags: {}, mode: {}, umask: {}, name: {:?} ...}}",
			self.flags,
			self.mode,
			self.umask,
			&self.name[..10]
		)
	}
}

pub fn create_create(
	path: &str,
	flags: u32,
	mode: u32,
) -> (Cmd<fuse_create_in>, Rsp<fuse_create_out>) {
	let cmd = fuse_create_in::new(path, flags, mode);
	let mut cmdhdr = create_in_header::<fuse_create_in>(Opcode::FUSE_CREATE);
	cmdhdr.nodeid = FUSE_ROOT_ID;
	let rsp = Default::default();
	let rsphdr = Default::default();
	(
		Cmd {
			cmd,
			header: cmdhdr,
			extra_buffer: None,
		},
		Rsp {
			rsp,
			header: rsphdr,
			extra_buffer: None,
		},
	)
}

pub const FUSE_SETUPMAPPING_ENTRIES: u64 = 8;
pub const FUSE_SETUPMAPPING_FLAG_WRITE: u64 = 1 << 0;
pub const FUSE_SETUPMAPPING_FLAG_READ: u64 = 1 << 1;
#[repr(C)]
#[derive(Debug, Default)]
pub struct fuse_setupmapping_in {
	pub fh: u64,
	pub foffset: u64,
	pub len: u64,
	pub flags: u64,
	pub moffset: u64,
}
unsafe impl FuseIn for fuse_setupmapping_in {}

#[repr(C)]
#[derive(Debug, Default)]
pub struct fuse_setupmapping_out {
	pub something1: [u8; 32],
	pub something2: [u8; 32],
	pub something3: [u8; 32],
}
unsafe impl FuseOut for fuse_setupmapping_out {}

pub fn create_setupmapping(
	fh: u64,
	foffset: u64,
	len: u64,
	flags: u64,
	moffset: u64,
) -> (Cmd<fuse_setupmapping_in>, Rsp<fuse_setupmapping_out>) {
	let cmd: fuse_setupmapping_in = fuse_setupmapping_in {
		fh,
		foffset,
		len,
		flags,
		moffset,
	};
	let mut cmdhdr = create_in_header::<fuse_setupmapping_in>(Opcode::FUSE_SETUPMAPPING);
	cmdhdr.nodeid = core::u64::MAX; // -1
	let rsp = Default::default();
	let rsphdr = Default::default();
	(
		Cmd {
			cmd,
			header: cmdhdr,
			extra_buffer: None,
		},
		Rsp {
			rsp,
			header: rsphdr,
			extra_buffer: None,
		},
	)
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct fuse_removemapping_in {
	pub count: u64,   // Currently only 1 supported.
	pub moffset: u64, // fuse_removemapping_one
	pub len: u64,     // fuse_removemapping_one
}
unsafe impl FuseIn for fuse_removemapping_in {}

#[repr(C)]
#[derive(Debug, Default)]
pub struct fuse_removemapping_out {}
unsafe impl FuseOut for fuse_removemapping_out {}

pub fn create_removemapping(
	nid: u64,
	moffset: u64,
	len: u64,
) -> (Cmd<fuse_removemapping_in>, Rsp<fuse_removemapping_out>) {
	let cmd: fuse_removemapping_in = fuse_removemapping_in {
		count: 1,
		moffset,
		len,
	};
	let mut cmdhdr = create_in_header::<fuse_removemapping_in>(Opcode::FUSE_REMOVEMAPPING);
	cmdhdr.nodeid = nid;
	let rsp = Default::default();
	let rsphdr = Default::default();
	(
		Cmd {
			cmd,
			header: cmdhdr,
			extra_buffer: None,
		},
		Rsp {
			rsp,
			header: rsphdr,
			extra_buffer: None,
		},
	)
}
