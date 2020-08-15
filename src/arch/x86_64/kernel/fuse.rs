// Copyright (c) 2020 Thomas Lambertz, RWTH Aachen University
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use super::fuse_dax::{CacheEntry, DaxAllocator, FuseDaxCache, FUSE_DAX_MEM_RANGE_SZ};
use super::fuse_h::*;
use crate::syscalls::fs::{self, FileError, FilePerms, PosixFile, PosixFileSystem, SeekWhence};
use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::{u32, u8};

// response out layout eg @ https://github.com/zargony/fuse-rs/blob/bf6d1cf03f3277e35b580f3c7b9999255d72ecf3/src/ll/request.rs#L44
// op in/out sizes/layout: https://github.com/hanwen/go-fuse/blob/204b45dba899dfa147235c255908236d5fde2d32/fuse/opcode.go#L439
// possible reponses for command: qemu/tools/virtiofsd/fuse_lowlevel.h

const FUSE_ENOENT_ID: u64 = 0;
const FUSE_ROOT_ID: u64 = 1;
const MAX_BUFFER_SIZE: usize = 0x1000 * 256;

pub trait FuseInterface {
	fn send_recv_buffers_blocking(
		&mut self,
		to_host: &[&[u8]],
		from_host: &[&mut [u8]],
	) -> Result<(), ()>;
}

/// Driver which can easily be copied into a FuseFile
/// Abstracts sending of a command over FuseInterface's byte arrays send/recv.
struct FuseDriver<T: FuseInterface>(Rc<RefCell<T>>);

impl<T: FuseInterface> FuseDriver<T> {
	/// Send a command via the fuse driver and get the response.
	/// Since responses can have different sizes, they are preallcoated by the caller.
	/// Ownership is passed, and returned when the request is completed.
	/// This call is blocking and only returns once the reply is available.
	pub fn handle_request<S, R>(&self, cmd: Cmd<S>, mut rsp: Rsp<R>) -> Result<Rsp<R>, FileError>
	where
		S: FuseIn + core::fmt::Debug,
		R: FuseOut + core::fmt::Debug,
	{
		trace!("Sending Fuse Command: {:?}", cmd);

		// Convert buffers to raw u8 slices so the backend can handle them.
		let to_host = cmd.as_u8bufs();
		let from_host = rsp.as_u8bufs_mut();

		// Send the buffers
		self.0
			.borrow_mut()
			.send_recv_buffers_blocking(&to_host, &from_host)
			.map_err(|_| FileError::EIO)?;

		// Got reply, return
		trace!("Got Fuse Reply: {:?}", rsp);
		Ok(rsp)
	}

	/// Send a command via the fuse driver, which does not expect a response.
	/// This call is blocking and returns once the receiver has acknowledged receiving the command.
	#[allow(dead_code)]
	pub fn send_command<S, R>(&self, cmd: Cmd<S>) -> Result<(), FileError>
	where
		S: FuseIn + core::fmt::Debug,
		R: FuseOut + core::fmt::Debug,
	{
		trace!("Sending Fuse Command: {:?}", cmd);

		// Convert buffers to raw u8 slices so the backend can handle them.
		let to_host = cmd.as_u8bufs();

		// Send the buffers
		self.0
			.borrow_mut()
			.send_recv_buffers_blocking(&to_host, &[])
			.map_err(|_| FileError::EIO)
	}

	/// #derive[Clone] does not work because of https://github.com/rust-lang/rust/issues/41481
	/// implement it ourselves
	pub fn clone(&self) -> Self {
		FuseDriver(self.0.clone())
	}
}

pub struct Fuse<T: FuseInterface> {
	driver: FuseDriver<T>,
	dax_allocator: Option<Rc<RefCell<DaxAllocator>>>,
	options: Option<Rc<FuseConnectionOptions>>,
}

struct FuseConnectionOptions {
	max_bufsize: usize,
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
			let entry = self.lookup(path)?;

			fuse_nid = entry.nodeid;
			fuse_attr = entry.attr;

			// 3.FUSE_OPEN(nodeid, O_RDONLY) -> fh
			let (cmd, rsp) = create_open(fuse_nid, perms.raw);
			let rsp = self.driver.handle_request(cmd, rsp)?;
			trace!("Open answer {:?}", rsp);
			fuse_fh = Some(rsp.rsp.fh);
		} else {
			// Create file. First look up parent.
			let (filename, parentid) = self.get_parent_id(path)?;

			// Create file as child in folder
			// (opens implicitly, returns results from both lookup and open calls)
			let (cmd, rsp) = create_create(parentid, filename, perms.raw, perms.mode);
			let rsp = self.driver.handle_request(cmd, rsp)?;
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
			connection_options: self.options.as_ref().unwrap().clone(), // unwrap can't fail, since we are initialized when opening
		};
		Ok(Box::new(file))
	}

	fn unlink(&self, path: &str) -> core::result::Result<(), FileError> {
		let (filename, parentid) = self.get_parent_id(path)?;

		let mut cmdhdr = create_in_header::<fuse_unlink_in>(Opcode::FUSE_UNLINK);
		cmdhdr.nodeid = parentid;

		let cmd: Cmd<fuse_unlink_in> = Cmd {
			cmd: filename.into(),
			header: cmdhdr,
			extra_buffer: FuseData(None),
		};
		let rsp: Rsp<fuse_unlink_out> = Rsp {
			rsp: Default::default(),
			header: Default::default(),
			extra_buffer: FuseData(None),
		};

		let rsp = self.driver.handle_request(cmd, rsp)?;
		trace!("unlink answer {:?}", rsp);

		Ok(())
	}

	fn stat(&self, filename: &str) -> Result<fs::Stat, FileError> {
		let feo = self.lookup(filename)?;

		Ok(fs::Stat {
			ino: feo.attr.ino,
			size: feo.attr.size,
			blocks: feo.attr.blocks,
			atime: feo.attr.atime,
			mtime: feo.attr.mtime,
			ctime: feo.attr.ctime,
			atimensec: feo.attr.atimensec,
			mtimensec: feo.attr.mtimensec,
			ctimensec: feo.attr.ctimensec,
			mode: feo.attr.mode,
			nlink: feo.attr.nlink,
			uid: feo.attr.uid,
			gid: feo.attr.gid,
			rdev: feo.attr.rdev,
			blksize: feo.attr.blksize,
			padding: feo.attr.padding,
		})
	}
}

impl<T: FuseInterface + 'static> Fuse<T> {
	pub fn new(driver: Rc<RefCell<T>>) -> Self {
		Self {
			driver: FuseDriver(driver),
			dax_allocator: None,
			options: None,
		}
	}

	pub fn new_with_dax(driver: Rc<RefCell<T>>, dax_allocator: DaxAllocator) -> Self {
		Self {
			driver: FuseDriver(driver),
			dax_allocator: Some(Rc::new(RefCell::new(dax_allocator))),
			options: None,
		}
	}

	pub fn send_init(&mut self) {
		let (cmd, rsp) = create_init();
		let rsp = self.driver.handle_request(cmd, rsp);
		trace!("fuse init answer: {:?}", rsp);

		let bufsize = if let Ok(rsp) = rsp {
			core::cmp::min(rsp.rsp.max_write as usize, MAX_BUFFER_SIZE)
		} else {
			error!("Fuse initialization failed!");
			0
		};

		self.options = Some(Rc::new(FuseConnectionOptions {
			max_bufsize: bufsize as usize,
		}));
	}

	/// Splits path at `/`, looks up the parents fuse id, returns it and the split filename.
	fn get_parent_id<'a>(&self, path: &'a str) -> Result<(&'a str, u64), FileError> {
		// Split path into name and folder.
		let mut pathiter = path.rsplitn(2, '/');
		let filename = match pathiter.next() {
			Some(x) => x,
			None => return Err(FileError::ENOENT),
		};
		let parentname = pathiter.next();

		// Look up folder id
		let parentid = if let Some(parentname) = parentname {
			self.lookup(parentname)?.nodeid
		} else {
			FUSE_ROOT_ID
		};

		Ok((filename, parentid))
	}

	/// Do recursive lookup of absolute path (omit the leading `/`). Split at `/`.
	/// Returns lookup entry of leaf file if it exists.
	pub fn lookup(&self, name: &str) -> Result<fuse_entry_out, FileError> {
		// All lookups start at root node
		let mut parent = FUSE_ROOT_ID;
		// Rust does not realize we always iterate at least once, so init with ENOENT
		let mut leaf = Err(FileError::ENOENT);
		for part in name.split('/') {
			let entry = self.lookup_single(part, parent)?;
			parent = entry.nodeid;
			leaf = Ok(entry);
		}
		leaf
	}

	/// Do single lookup of filename from fuse root_nid. name must not contain `/`.
	/// Returns ENOENT if the file does not exist.
	pub fn lookup_single(&self, name: &str, root_nid: u64) -> Result<fuse_entry_out, FileError> {
		trace!("Lookup for {}", name);
		let mut cmdhdr = create_in_header::<fuse_lookup_in>(Opcode::FUSE_LOOKUP);
		cmdhdr.nodeid = root_nid;
		let cmd: Cmd<fuse_lookup_in> = Cmd {
			cmd: name.into(),
			header: cmdhdr,
			extra_buffer: FuseData(None),
		};
		let rsp: Rsp<fuse_entry_out> = Rsp {
			rsp: Default::default(),
			header: Default::default(),
			extra_buffer: FuseData(None),
		};
		let rsp = self.driver.handle_request(cmd, rsp)?;
		trace!("result: {:?}", rsp);
		if rsp.rsp.nodeid == FUSE_ENOENT_ID {
			// nodeid == 0 is the same as -ENOENT
			return Err(FileError::ENOENT);
		}
		// File exists, return attributes
		Ok(rsp.rsp)
	}
}

struct FuseFile<T: FuseInterface> {
	driver: FuseDriver<T>,
	fuse_nid: Option<u64>,
	fuse_fh: Option<u64>,
	offset: usize,
	dax_cache: Option<FuseDaxCache>,
	attr: fuse_attr,
	open_options: FilePerms,
	connection_options: Rc<FuseConnectionOptions>,
}

impl<T: FuseInterface> FuseFile<T> {
	/// Reads the file using normal fuse read commands. File contents are in fuse reply
	fn read_fuse(&mut self, buf: &mut [u8]) -> Result<Vec<u8>, FileError> {
		let mut len = buf.len();
		if len > self.connection_options.max_bufsize {
			debug!("Reading longer than max_read_len: {}", len);
			len = self.connection_options.max_bufsize;
		}
		if let Some(fh) = self.fuse_fh {
			let (cmd, rsp) = create_read(fh, len as u32, self.offset as u64);
			let rsp = self.driver.handle_request(cmd, rsp)?;
			let len = rsp.header.len as usize - ::core::mem::size_of::<fuse_out_header>();
			self.offset += len;
			// TODO: do this zerocopy
			let mut vec = rsp.extra_buffer.0.unwrap();
			vec.truncate(len);
			trace!("LEN: {}, VEC: {:?}", len, vec);
			Ok(vec)
		} else {
			warn!("File not open, cannot read!");
			Err(FileError::ENOENT)
		}
	}

	/// Uses fuse setupmapping to create a DAX mapping, and copies from that. Mappings are cached
	fn read_dax(&mut self, buf: &mut [u8]) -> Result<usize, FileError> {
		trace!("read_dax({:x}) from offset {:x}", buf.len(), self.offset);
		let mut cached = self.get_cached()?.clone();
		let cached = cached.as_buf(self.offset);
		trace!("Got dax cache as {:p}", cached.as_ptr());
		// Limit read length to buffer boundary
		let mut len = buf.len();
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
		let read_bytes = len;
		trace!(
			"Starting dax copy. {:p}, {:#x}, {:p}, {:#x}",
			buf.as_ptr(),
			buf.len(),
			cached.as_ptr(),
			cached.len()
		);
		buf[..read_bytes].copy_from_slice(&cached[..len]);

		trace!(
			"read_dax output: {:?} ....",
			&buf[..core::cmp::min(16, buf.len())]
		);
		Ok(read_bytes as u64)
	}

	fn write_fuse(&mut self, buf: &[u8]) -> Result<u64, FileError> {
		let mut len = buf.len();
		if len > self.connection_options.max_bufsize {
			debug!(
				"Writing longer than max_write_len: {} > {}",
				buf.len(),
				self.connection_options.max_bufsize
			);
			len = self.connection_options.max_bufsize;
		}
		if let Some(fh) = self.fuse_fh {
			let (cmd, rsp) = create_write(fh, &buf[..len], self.offset as u64);
			let rsp = self.driver.handle_request(cmd, rsp)?;
			trace!("write response: {:?}", rsp);

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
			Ok(len)
		} else {
			warn!("File not open, cannot read!");
			Err(FileError::ENOENT)
		}
	}

	fn write_dax(&mut self, buf: &[u8]) -> Result<usize, FileError> {
		let mut len = buf.len() as usize;

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

		trace!(
			"write_dax({:x}) from offset {:x} [{:x}]",
			len,
			self.offset,
			self.attr.size
		);

		let mut cached = self.get_cached()?.clone();
		let cached = cached.as_buf(self.offset);

		// Limit write length to buffer boundary
		if cached.len() < len {
			len = cached.len();
		}

		self.offset += len;

		// Write buffer into cache.
		trace!(
			"copying data to slice! from {:p} to {:p} of len {:x}",
			buf.as_ptr(),
			cached.as_ptr(),
			len
		);
		cached[..len].copy_from_slice(buf);

		Ok(len)
	}

	/// Returns true if the file is opened with write flag
	fn writable(&self) -> bool {
		self.open_options.write // && self.attr.mode & 0o222 > 0
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
			.alloc_cache(self.offset)
			.expect("Could not alloc DAX cache"); // TODO: free cache entry, try again
		if let Some(fh) = self.fuse_fh {
			let mut flags = FUSE_SETUPMAPPING_FLAG_READ;
			if self.writable() {
				flags |= FUSE_SETUPMAPPING_FLAG_WRITE;
			}
			// always allocate aligned blocks, so we never have a duplicate mapping
			let foffset = align_down!(self.offset as u64, FUSE_DAX_MEM_RANGE_SZ);
			let (cmd, rsp) = create_setupmapping(
				fh,
				foffset,
				FUSE_DAX_MEM_RANGE_SZ as u64,
				flags,
				entry.get_moffset(),
			);
			let _rsp = self.driver.handle_request(cmd, rsp)?;
			// TODO: check for errors. mapping might have failed.

			trace!("Mapped new dax entry {:?}", entry);
			Ok(entry)
		} else {
			warn!("File not open, cannot use dax!");
			Err(FileError::ENOENT)
		}
	}

	/// Drops all DAX mappings
	fn drop_cache(&mut self) {
		if let Some(cache) = &mut self.dax_cache {
			let mut mappings = Vec::new();
			cache.iterate_run(|_addr, entry| {
				mappings.push(fuse_removemapping_one {
					moffset: entry.get_moffset(),
					len: FUSE_DAX_MEM_RANGE_SZ,
				})
			});
			if mappings.is_empty() {
				return;
			}
			trace!("Removing dax mappings {:?}", mappings);
			let (cmd, rsp) = create_removemapping(self.fuse_nid.unwrap_or(0), &mappings);
			if self.driver.handle_request(cmd, rsp).is_err() {
				error!("Unmapping DAX failed. Continuing assuming it succeeded");
			}

			cache.free();
		}
	}
}

impl<T: FuseInterface> PosixFile for FuseFile<T> {
	fn close(&mut self) -> Result<(), FileError> {
		self.drop_cache();
		let (cmd, rsp) = create_release(self.fuse_nid.unwrap(), self.fuse_fh.unwrap());
		self.driver.handle_request(cmd, rsp)?;

		Ok(())
	}

	fn read(&mut self, buf: &mut [u8]) -> Result<usize, FileError> {
		if self.dax_cache.is_some() {
			self.read_dax(buf)
		} else {
			let read = self.read_fuse(buf)?;
			let read_bytes = read.len();
			buf[..read_bytes].copy_from_slice(&read);
			Ok(read_bytes)
		}
	}

	fn write(&mut self, buf: &[u8]) -> Result<usize, FileError> {
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

	fn fsync(&mut self) -> Result<(), FileError> {
		debug!("fuse fsync");
		//Err(FileError::ENOSYS)

		let cmd = fuse_fsync_in {
			fh: self.fuse_fh.unwrap(), // TODO: error.
			fsync_flags: 0,
			padding: 0,
		};
		let mut cmdhdr = create_in_header::<fuse_fsync_in>(Opcode::FUSE_FSYNC);

		let rsp = fuse_fsync_out {};
		let rsphdr: fuse_out_header = Default::default();

		cmdhdr.nodeid = self.fuse_nid.unwrap(); // TODO: error.

		let _rsp = self.driver.handle_request(
			Cmd {
				cmd,
				header: cmdhdr,
				extra_buffer: FuseData(None),
			},
			Rsp {
				rsp,
				header: rsphdr,
				extra_buffer: FuseData(None),
			},
		)?;

		Ok(())
	}
}

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
			extra_buffer: FuseData(None),
		},
		Rsp {
			rsp,
			header: rsphdr,
			extra_buffer: FuseData(None),
		},
	)
}

pub fn create_removemapping(
	nid: u64,
	mappings: &Vec<fuse_removemapping_one>,
) -> (Cmd<fuse_removemapping_in>, Rsp<fuse_removemapping_out>) {
	let cmd: fuse_removemapping_in = fuse_removemapping_in {
		count: mappings.len() as u32,
	};
	let mut cmdhdr = create_in_header::<fuse_removemapping_in>(Opcode::FUSE_REMOVEMAPPING);
	cmdhdr.nodeid = nid;
	let rsp = Default::default();

	// Get u8buf of Vec
	// TODO: create an interface that allows this without copying.
	let byte_ptr = mappings.as_ptr() as *const u8;
	let byte_len = mappings.len() * core::mem::size_of::<fuse_removemapping_one>();
	let byte_arr = unsafe { core::slice::from_raw_parts(byte_ptr, byte_len) };
	let extra = Vec::from(byte_arr);

	let rsphdr = Default::default();
	(
		Cmd {
			cmd,
			header: cmdhdr,
			extra_buffer: FuseData(Some(extra)),
		},
		Rsp {
			rsp,
			header: rsphdr,
			extra_buffer: FuseData(None),
		},
	)
}

pub fn create_create(
	fuse_nid: u64,
	path: &str,
	flags: u32,
	mode: u32,
) -> (Cmd<fuse_create_in>, Rsp<fuse_create_out>) {
	let cmd = fuse_create_in::new(path, flags, mode);
	let mut cmdhdr = create_in_header::<fuse_create_in>(Opcode::FUSE_CREATE);
	cmdhdr.nodeid = fuse_nid;
	let rsp = Default::default();
	let rsphdr = Default::default();
	(
		Cmd {
			cmd,
			header: cmdhdr,
			extra_buffer: FuseData(None),
		},
		Rsp {
			rsp,
			header: rsphdr,
			extra_buffer: FuseData(None),
		},
	)
}

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
			extra_buffer: FuseData(None),
		},
		Rsp {
			rsp,
			header: rsphdr,
			extra_buffer: FuseData(None),
		},
	)
}

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
			extra_buffer: FuseData(None),
		},
		Rsp {
			rsp,
			header: rsphdr,
			extra_buffer: FuseData(None),
		},
	)
}

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
			extra_buffer: FuseData(Some(writebuf)),
		},
		Rsp {
			rsp,
			header: rsphdr,
			extra_buffer: FuseData(None),
		},
	)
}

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
			extra_buffer: FuseData(None),
		},
		Rsp {
			rsp,
			header: rsphdr,
			extra_buffer: FuseData(Some(readbuf)),
		},
	)
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
		flags: FUSE_MAX_PAGES, // Use max_pages so we can have reads/writes up to 256 pages instead of 32 pages.
	};
	let cmdhdr = create_in_header::<fuse_init_in>(Opcode::FUSE_INIT);
	let rsp: fuse_init_out = Default::default();
	let rsphdr: fuse_out_header = Default::default();
	(
		Cmd {
			cmd,
			header: cmdhdr,
			extra_buffer: FuseData(None),
		},
		Rsp {
			rsp,
			header: rsphdr,
			extra_buffer: FuseData(None),
		},
	)
}
