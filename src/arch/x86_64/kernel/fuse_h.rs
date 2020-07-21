use alloc::vec::Vec;
use core::fmt;

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

/// Stores read/write buffers
pub struct FuseData(pub Option<Vec<u8>>);

/// Print a maximum of 16 hex-chars for each buffer!
impl fmt::Debug for FuseData {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		if let Some(buf) = &self.0 {
			if buf.len() <= 16 {
				write!(f, "{:x?}", buf)
			} else {
				// We are longer than 16 chars, truncate!
				write!(
					f,
					"{:x?} (truncated from {:#x} bytes)",
					&buf[..16],
					buf.len()
				)
			}
		} else {
			write!(f, "None")
		}
	}
}

#[repr(C)]
#[derive(Debug)]
pub struct Cmd<T: FuseIn + core::fmt::Debug> {
	pub header: fuse_in_header,
	pub cmd: T,
	pub extra_buffer: FuseData, // eg for writes. allows zero-copy and avoids rust size_of operations (which always add alignment padding)
}

#[repr(C)]
#[derive(Debug)]
pub struct Rsp<T: FuseOut + core::fmt::Debug> {
	pub header: fuse_out_header,
	pub rsp: T,
	pub extra_buffer: FuseData, // eg for reads. allows zero-copy and avoids rust size_of operations (which always add alignment padding)
}

// TODO: use from/into? But these require consuming the command, so we need some better memory model to avoid deallocation
impl<T> Cmd<T>
where
	T: FuseIn + core::fmt::Debug,
{
	/// Returns vec of u8 buffers of different parts of the command, such that fuse host can interpret them.
	/// Splits header and cmd into two, so virtiofsd fast write path works.
	pub fn as_u8bufs(&self) -> Vec<&[u8]> {
		let rawheader = unsafe {
			::core::slice::from_raw_parts(
				(&self.header as *const fuse_in_header) as *const u8,
				::core::mem::size_of::<fuse_in_header>(),
			)
		};
		let rawcmd = unsafe {
			::core::slice::from_raw_parts(
				(&self.cmd as *const T) as *const u8,
				::core::mem::size_of::<T>(),
			)
		};
		//info!("{:#?}, {:#?}", rawheader, rawcmd);
		if let Some(extra) = &self.extra_buffer.0 {
			vec![rawheader, rawcmd, &extra.as_ref()]
		} else {
			vec![rawheader, rawcmd]
		}
	}
}

impl<T> Rsp<T>
where
	T: FuseOut + core::fmt::Debug,
{
	/// Returns Vec of mutable u8 buffers.
	/// We don't split header and response here, but could do so if we want and still have the fast write case.
	pub fn as_u8bufs_mut(&mut self) -> Vec<&mut [u8]> {
		let rawrsp = unsafe {
			::core::slice::from_raw_parts_mut(
				(&mut self.header as *mut fuse_out_header) as *mut u8,
				::core::mem::size_of::<T>() + ::core::mem::size_of::<fuse_out_header>(),
			)
		};
		if let Some(extra) = self.extra_buffer.0.as_mut() {
			vec![rawrsp, extra]
		} else {
			vec![rawrsp]
		}
	}
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

/**
 * INIT request/reply flags
 *
 * FUSE_ASYNC_READ: asynchronous read requests
 * FUSE_POSIX_LOCKS: remote locking for POSIX file locks
 * FUSE_FILE_OPS: kernel sends file handle for fstat, etc... (not yet supported)
 * FUSE_ATOMIC_O_TRUNC: handles the O_TRUNC open flag in the filesystem
 * FUSE_EXPORT_SUPPORT: filesystem handles lookups of "." and ".."
 * FUSE_BIG_WRITES: filesystem can handle write size larger than 4kB
 * FUSE_DONT_MASK: don't apply umask to file mode on create operations
 * FUSE_SPLICE_WRITE: kernel supports splice write on the device
 * FUSE_SPLICE_MOVE: kernel supports splice move on the device
 * FUSE_SPLICE_READ: kernel supports splice read on the device
 * FUSE_FLOCK_LOCKS: remote locking for BSD style file locks
 * FUSE_HAS_IOCTL_DIR: kernel supports ioctl on directories
 * FUSE_AUTO_INVAL_DATA: automatically invalidate cached pages
 * FUSE_DO_READDIRPLUS: do READDIRPLUS (READDIR+LOOKUP in one)
 * FUSE_READDIRPLUS_AUTO: adaptive readdirplus
 * FUSE_ASYNC_DIO: asynchronous direct I/O submission
 * FUSE_WRITEBACK_CACHE: use writeback cache for buffered writes
 * FUSE_NO_OPEN_SUPPORT: kernel supports zero-message opens
 * FUSE_PARALLEL_DIROPS: allow parallel lookups and readdir
 * FUSE_HANDLE_KILLPRIV: fs handles killing suid/sgid/cap on write/chown/trunc
 * FUSE_POSIX_ACL: filesystem supports posix acls
 * FUSE_ABORT_ERROR: reading the device after abort returns ECONNABORTED
 * FUSE_MAX_PAGES: init_out.max_pages contains the max number of req pages
 * FUSE_CACHE_SYMLINKS: cache READLINK responses
 * FUSE_NO_OPENDIR_SUPPORT: kernel supports zero-message opendir
 * FUSE_EXPLICIT_INVAL_DATA: only invalidate cached pages on explicit request
 * FUSE_MAP_ALIGNMENT: map_alignment field is valid
 */
pub const FUSE_ASYNC_READ: u32 = 1 << 0;
pub const FUSE_POSIX_LOCKS: u32 = 1 << 1;
pub const FUSE_FILE_OPS: u32 = 1 << 2;
pub const FUSE_ATOMIC_O_TRUNC: u32 = 1 << 3;
pub const FUSE_EXPORT_SUPPORT: u32 = 1 << 4;
pub const FUSE_BIG_WRITES: u32 = 1 << 5;
pub const FUSE_DONT_MASK: u32 = 1 << 6;
pub const FUSE_SPLICE_WRITE: u32 = 1 << 7;
pub const FUSE_SPLICE_MOVE: u32 = 1 << 8;
pub const FUSE_SPLICE_READ: u32 = 1 << 9;
pub const FUSE_FLOCK_LOCKS: u32 = 1 << 10;
pub const FUSE_HAS_IOCTL_DIR: u32 = 1 << 11;
pub const FUSE_AUTO_INVAL_DATA: u32 = 1 << 12;
pub const FUSE_DO_READDIRPLUS: u32 = 1 << 13;
pub const FUSE_READDIRPLUS_AUTO: u32 = 1 << 14;
pub const FUSE_ASYNC_DIO: u32 = 1 << 15;
pub const FUSE_WRITEBACK_CACHE: u32 = 1 << 16;
pub const FUSE_NO_OPEN_SUPPORT: u32 = 1 << 17;
pub const FUSE_PARALLEL_DIROPS: u32 = 1 << 18;
pub const FUSE_HANDLE_KILLPRIV: u32 = 1 << 19;
pub const FUSE_POSIX_ACL: u32 = 1 << 20;
pub const FUSE_ABORT_ERROR: u32 = 1 << 21;
pub const FUSE_MAX_PAGES: u32 = 1 << 22;
pub const FUSE_CACHE_SYMLINKS: u32 = 1 << 23;
pub const FUSE_NO_OPENDIR_SUPPORT: u32 = 1 << 24;
pub const FUSE_EXPLICIT_INVAL_DATA: u32 = 1 << 25;
pub const FUSE_MAP_ALIGNMENT: u32 = 1 << 26;

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

// TODO: max path length?
const MAX_PATH_LEN: usize = 256;
fn str_to_path(s: &str) -> [u8; MAX_PATH_LEN] {
	let mut buf = [0 as u8; MAX_PATH_LEN];
	str_into_u8buf(s, &mut buf);
	buf
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
	pub fn new(name: &str, flags: u32, mode: u32) -> Self {
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

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct fuse_removemapping_in {
	pub count: u32,
}
unsafe impl FuseIn for fuse_removemapping_in {}

#[repr(C)]
#[derive(Debug, Default)]
pub struct fuse_removemapping_out {}
unsafe impl FuseOut for fuse_removemapping_out {}

#[repr(C)]
#[derive(Debug, Default)]
pub struct fuse_removemapping_one {
	pub moffset: u64,
	pub len: u64,
}
