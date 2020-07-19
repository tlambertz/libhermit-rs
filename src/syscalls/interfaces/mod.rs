// Copyright (c) 2018 Stefan Lankes, RWTH Aachen University
//                    Colin Finck, RWTH Aachen University
//               2020 Thomas Lambertz, RWTH Aachen University
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::convert::{TryFrom, TryInto};
use core::fmt::Write;
use core::{isize, ptr, slice, str};

use crate::arch;
use crate::console;
use crate::environment;
use crate::errno::*;
use crate::synch::spinlock::SpinlockIrqSave;
use crate::syscalls::fs::{self, FilePerms, PosixFile, SeekWhence};
use crate::util;

pub use self::generic::*;
pub use self::uhyve::*;

mod generic;
mod uhyve;

static DRIVER_LOCK: SpinlockIrqSave<()> = SpinlockIrqSave::new(());

const SEEK_SET: i32 = 0;
const SEEK_CUR: i32 = 1;
const SEEK_END: i32 = 2;

impl TryFrom<i32> for SeekWhence {
	type Error = &'static str;

	fn try_from(value: i32) -> Result<Self, Self::Error> {
		match value {
			SEEK_CUR => Ok(SeekWhence::Cur),
			SEEK_SET => Ok(SeekWhence::Set),
			SEEK_END => Ok(SeekWhence::End),
			_ => Err("Got invalid seek whence parameter!"),
		}
	}
}

/// Stat object as passed by newlib
// `gcc -g -c test.c && pahole test.o -C stat` outputs the following fields+sizes when using newlib
// type resolution with `gcc -E test.c`
// They are ordered in a way such that padding is not necessary
#[repr(C, packed)]
#[derive(Debug)]
#[cfg(feature = "newlib")]
struct stat {
	st_dev: i16,		// dev_t		
	st_ino: u16,		// ino_t		
	st_mode: u32,		// mode_t		
	st_nlink: u16,		// nlink_t		
	st_uid: u16,		// uid_t		
	st_gid: u16,		// gid_t		
	st_rdev: i16,		// dev_t		
	st_size: i64,		// off_t		
	st_atime: i64,		// time_t		
	st_spare1: i64,		// long		
	st_mtime: i64,		// time_t		
	st_spare2: i64,		// long		
	st_ctime: i64,		// time_t		
	st_spare3: i64,		// long		
	st_blksize: i64,	// blksize_t	
	st_blocks: i64,		// blkcnt_t	
	st_spare4_0: i64,	// long		
	st_spare4_1: i64,	// long		
}

// TODO: these are defined in hermit-abi. Should we use a constants crate imported in both?
//const O_RDONLY: i32 = 0o0000;
const O_WRONLY: i32 = 0o0001;
const O_RDWR: i32 = 0o0002;
const O_CREAT: i32 = 0o0100;
const O_EXCL: i32 = 0o0200;
const O_TRUNC: i32 = 0o1000;
const O_APPEND: i32 = 0o2000;
const O_DIRECT: i32 = 0o40000;

fn open_flags_to_perm(flags: i32, mut mode: u32) -> FilePerms {

	// TODO: this is fixed in stdlib, can we remote it?
	if mode & 0o777 != mode {
		// mode is passed in as hex (0x777). Linux/Fuse expects octal (0o777).
		// just passing mode as is to FUSE create, leads to very weird permissions: 0b0111_0111_0111 -> 'r-x rwS rwt'
		mode =
			match mode {
				0x777 => 0o777,
				0 => 0,
				_ => {
					info!("Mode neither 0x777 nor 0x0, should never happen with current hermit stdlib! Using 777 instead of {:o}", mode);
					0o777
				}
			};
	}

	let mut perms = FilePerms {
		raw: flags as u32,
		mode,
		..Default::default()
	};
	perms.write = flags & (O_WRONLY | O_RDWR) != 0;
	perms.creat = flags & (O_CREAT) != 0;
	perms.excl = flags & (O_EXCL) != 0;
	perms.trunc = flags & (O_TRUNC) != 0;
	perms.append = flags & (O_APPEND) != 0;
	perms.directio = flags & (O_DIRECT) != 0;
	if flags & !(O_WRONLY | O_RDWR | O_CREAT | O_EXCL | O_TRUNC | O_APPEND | O_DIRECT) != 0 {
		warn!("Unknown file flags used! {}", flags);
	}
	perms
}

pub trait SyscallInterface: Send + Sync {
	fn init(&self) {
		// Interface-specific initialization steps.
	}

	fn get_application_parameters(&self) -> (i32, *const *const u8, *const *const u8) {
		let mut argv = Vec::new();

		let name = Box::leak(Box::new("{name}\0")).as_ptr();
		argv.push(name);

		if let Some(args) = environment::get_command_line_argv() {
			debug!("Setting argv as: {:?}", args);
			for a in args {
				let ptr = Box::leak(format!("{}\0", a).into_boxed_str()).as_ptr();
				argv.push(ptr);
			}
		}

		let environ = ptr::null() as *const *const u8;

		let argc = argv.len() as i32;
		let argv = Box::leak(argv.into_boxed_slice()).as_ptr();

		(argc, argv, environ)
	}

	fn shutdown(&self, _arg: i32) -> ! {
		arch::processor::shutdown()
	}

	fn get_mac_address(&self) -> Result<[u8; 6], ()> {
		let _lock = DRIVER_LOCK.lock();

		match arch::kernel::pci::get_network_driver() {
			Some(driver) => Ok(driver.borrow().get_mac_address()),
			_ => Err(()),
		}
	}

	fn get_mtu(&self) -> Result<u16, ()> {
		let _lock = DRIVER_LOCK.lock();

		match arch::kernel::pci::get_network_driver() {
			Some(driver) => Ok(driver.borrow().get_mtu()),
			_ => Err(()),
		}
	}

	fn has_packet(&self) -> bool {
		let _lock = DRIVER_LOCK.lock();

		match arch::kernel::pci::get_network_driver() {
			Some(driver) => driver.borrow().has_packet(),
			_ => false,
		}
	}

	fn get_tx_buffer(&self, len: usize) -> Result<(*mut u8, usize), ()> {
		let _lock = DRIVER_LOCK.lock();

		match arch::kernel::pci::get_network_driver() {
			Some(driver) => driver.borrow_mut().get_tx_buffer(len),
			_ => Err(()),
		}
	}

	fn send_tx_buffer(&self, handle: usize, len: usize) -> Result<(), ()> {
		let _lock = DRIVER_LOCK.lock();

		match arch::kernel::pci::get_network_driver() {
			Some(driver) => driver.borrow_mut().send_tx_buffer(handle, len),
			_ => Err(()),
		}
	}

	fn receive_rx_buffer(&self) -> Result<&'static [u8], ()> {
		let _lock = DRIVER_LOCK.lock();

		match arch::kernel::pci::get_network_driver() {
			Some(driver) => driver.borrow().receive_rx_buffer(),
			_ => Err(()),
		}
	}

	fn rx_buffer_consumed(&self) -> Result<(), ()> {
		let _lock = DRIVER_LOCK.lock();

		match arch::kernel::pci::get_network_driver() {
			Some(driver) => {
				driver.borrow_mut().rx_buffer_consumed();
				Ok(())
			}
			_ => Err(()),
		}
	}

	#[cfg(not(target_arch = "x86_64"))]
	fn unlink(&self, _name: *const u8) -> i32 {
		debug!("unlink is unimplemented, returning -ENOSYS");
		-ENOSYS
	}

	#[cfg(target_arch = "x86_64")]
	fn unlink(&self, name: *const u8) -> i32 {
		let name = unsafe { util::c_str_to_str(name) };
		debug!("unlink {}", name);

		fs::FILESYSTEM
			.lock()
			.unlink(&name)
			.expect("Unlinking failed!"); // TODO: error handling
		0
	}

	#[cfg(not(target_arch = "x86_64"))]
	fn open(&self, _name: *const u8, _flags: i32, _mode: i32) -> i32 {
		debug!("open is unimplemented, returning -ENOSYS");
		-ENOSYS
	}

	#[cfg(target_arch = "x86_64")]
	fn open(&self, name: *const u8, flags: i32, mode: i32) -> i32 {
		//! mode is 0x777 (0b0111_0111_0111), when flags | O_CREAT, else 0
		//! flags is bitmask of O_DEC_* defined above.
		//! (taken from rust stdlib/sys hermit target )

		let name = unsafe { util::c_str_to_str(name) };
		debug!("Open {}, {}, {}", name, flags, mode);

		let mut fs = fs::FILESYSTEM.lock();
		let fd = fs.open(&name, open_flags_to_perm(flags, mode as u32));

		if let Ok(fd) = fd {
			fd as i32
		} else {
			-1
		}
	}

	fn close(&self, fd: i32) -> i32 {
		// we don't have to close standard descriptors
		if fd < 3 {
			return 0;
		}

		let mut fs = fs::FILESYSTEM.lock();
		fs.close(fd as u64);
		0
	}

	#[cfg(not(target_arch = "x86_64"))]
	fn read(&self, _fd: i32, _buf: *mut u8, _len: usize) -> isize {
		debug!("read is unimplemented, returning -ENOSYS");
		-ENOSYS as isize
	}

	#[cfg(target_arch = "x86_64")]
	fn read(&self, fd: i32, buf: *mut u8, len: usize) -> isize {
		debug!("Read! {}, {}", fd, len);

		// TODO: assert that buf is valid in userspace
		let buf = unsafe{core::slice::from_raw_parts_mut(buf, len)};

		let mut fs = fs::FILESYSTEM.lock();
		let mut read_bytes = 0;
		fs.fd_op(fd as u64, |file| {
			read_bytes = file.unwrap().read(buf).unwrap(); // TODO: might fail
		});

		read_bytes as isize
	}

	fn write(&self, fd: i32, buf: *const u8, len: usize) -> isize {
		assert!(len <= isize::MAX as usize);

		if fd > 2 {
			// Normal file
			let buf = unsafe { slice::from_raw_parts(buf, len) };

			let mut written_bytes = 0;
			let mut fs = fs::FILESYSTEM.lock();
			fs.fd_op(fd as u64, |file| {
				written_bytes = file.unwrap().write(buf).unwrap(); // TODO: might fail
			});
			debug!("Write done! {}", written_bytes);
			written_bytes as isize
		} else {
			// stdin/err/out all go to console
			unsafe {
				let slice = slice::from_raw_parts(buf, len);
				console::CONSOLE
					.lock()
					.write_str(str::from_utf8_unchecked(slice))
					.unwrap();
			}

			len as isize
		}
	}

	fn lseek(&self, fd: i32, offset: isize, whence: i32) -> isize {
		debug!("lseek! {}, {}, {}", fd, offset, whence);

		let mut fs = fs::FILESYSTEM.lock();
		let mut ret = 0;
		fs.fd_op(fd as u64, |file| {
			ret = file.unwrap().lseek(offset, whence.try_into().unwrap()).unwrap(); // TODO: might fail
		});

		ret as isize
	}


	#[cfg(feature = "newlib")]
	fn stat(&self, filename: *const u8, st: usize) -> i32 {
		let filename = unsafe { util::c_str_to_str(filename) };
		let st = st as *mut stat;

		trace!("stat {}", filename);

		let mut fs = fs::FILESYSTEM.lock();
		let stat = fs.stat(&filename);
		
		trace!("fuse: {:?}", stat);
		if let Ok(stat) = stat {
			unsafe {
				(*st).st_dev = 0;
				(*st).st_ino = 42; // stat.ino is too big
				(*st).st_mode = stat.mode;
				(*st).st_nlink = stat.nlink.try_into().unwrap();
				(*st).st_uid = 0; // stat.uid
				(*st).st_gid = 0; // stat.gid
				(*st).st_rdev = stat.rdev.try_into().unwrap();
				(*st).st_size = stat.size.try_into().unwrap();
				(*st).st_atime = stat.atime.try_into().unwrap();
				(*st).st_spare1 = 0;
				(*st).st_mtime = stat.mtime.try_into().unwrap();
				(*st).st_spare2 = 0;
				(*st).st_ctime = stat.ctime.try_into().unwrap();
				(*st).st_spare3 = 0;
				(*st).st_blksize = stat.blksize.try_into().unwrap();
				(*st).st_blocks = stat.blocks.try_into().unwrap();
				(*st).st_spare4_0 = 0;
				(*st).st_spare4_1 = 0;
			}
			0
		} else {
			-1
		}
	}

	#[cfg(not(feature = "newlib"))]
	fn stat(&self, _file: *const u8, _st: usize) -> i32 {
		info!("stat is unimplemented");
		-ENOSYS
	}
}
