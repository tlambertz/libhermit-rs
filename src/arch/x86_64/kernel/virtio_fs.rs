// Copyright (c) 2020 Thomas Lambertz, RWTH Aachen University
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::arch::x86_64::kernel::fuse::{Fuse, FuseInterface};
use crate::arch::x86_64::kernel::pci;
use crate::arch::x86_64::kernel::virtio::{
	self, consts::*, virtio_pci_common_cfg, VirtioNotification, VirtioSharedMemory, Virtq,
};
use crate::syscalls::fs;
use crate::util;

use super::fuse_dax::DaxAllocator;
use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::{fmt, u32, u8};

pub const VIRTIO_FS_SHMCAP_ID_CACHE: u8 = 0;

#[repr(C)]
struct virtio_fs_config {
	/* Filesystem name (UTF-8, not NUL-terminated, padded with NULs) */
	tag: [u8; 36],
	/* Number of request queues */
	num_request_queues: u32,
}

impl fmt::Debug for virtio_fs_config {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(
			f,
			"virtio_fs_config {{ tag: '{}', num_request_queues: {} }}",
			core::str::from_utf8(&self.tag).unwrap(),
			self.num_request_queues
		)
	}
}

pub struct VirtioFsDriver<'a> {
	common_cfg: &'a mut virtio_pci_common_cfg,
	device_cfg: &'a virtio_fs_config,
	notify_cfg: VirtioNotification,
	shm_cfg: Option<VirtioSharedMemory>,
	vqueues: Option<Vec<Virtq<'a>>>,
}

impl<'a> fmt::Debug for VirtioFsDriver<'a> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "VirtioFsDriver {{ ")?;
		write!(f, "common_cfg: {:?}, ", self.common_cfg)?;
		write!(f, "device_cfg: {:?}, ", self.device_cfg)?;
		write!(f, "nofity_cfg: {:?}, ", self.notify_cfg)?;
		match &self.vqueues {
			None => write!(f, "Uninitialized VQs")?,
			Some(vqs) => write!(f, "Initialized {} VQs", vqs.len())?,
		}
		write!(f, " }}")
	}
}

impl VirtioFsDriver<'_> {
	pub fn init_vqs(&mut self) {
		let common_cfg = &mut self.common_cfg;
		let device_cfg = &self.device_cfg;
		let notify_cfg = &mut self.notify_cfg;

		// 4.1.5.1.3 Virtqueueu configuration
		// see https://elixir.bootlin.com/linux/latest/ident/virtio_fs_setup_vqs for example
		debug!("Setting up virtqueues...");

		if device_cfg.num_request_queues == 0 {
			error!("0 request queues requested from device. Aborting!");
			return;
		}
		// 1 highprio queue, and n normal request queues
		let vqnum = device_cfg.num_request_queues + 1;
		let mut vqueues = Vec::<Virtq>::new();

		// create the queues and tell device about them
		for i in 0..vqnum as u16 {
			// TODO: catch error
			let vq = Virtq::new_from_common(i, common_cfg, notify_cfg).unwrap();
			vqueues.push(vq);
		}

		self.vqueues = Some(vqueues);
	}

	pub fn negotiate_features(&mut self) {
		let common_cfg = &mut self.common_cfg;
		// Linux kernel reads 2x32 featurebits: https://elixir.bootlin.com/linux/latest/ident/vp_get_features
		common_cfg.device_feature_select = 0;
		let mut device_features: u64 = common_cfg.device_feature as u64;
		common_cfg.device_feature_select = 1;
		device_features |= (common_cfg.device_feature as u64) << 32;

		if device_features & VIRTIO_F_RING_INDIRECT_DESC != 0 {
			debug!("Device offers feature VIRTIO_F_RING_INDIRECT_DESC, ignoring");
		}
		if device_features & VIRTIO_F_RING_EVENT_IDX != 0 {
			debug!("Device offers feature VIRTIO_F_RING_EVENT_IDX, ignoring");
		}
		if device_features & VIRTIO_F_VERSION_1 != 0 {
			debug!("Device offers feature VIRTIO_F_VERSION_1, accepting.");
			common_cfg.driver_feature_select = 1;
			common_cfg.driver_feature = (VIRTIO_F_VERSION_1 >> 32) as u32;
		}
		if device_features
			& !(VIRTIO_F_RING_INDIRECT_DESC | VIRTIO_F_RING_EVENT_IDX | VIRTIO_F_VERSION_1)
			!= 0
		{
			debug!(
				"Device offers unknown feature bits: {:064b}.",
				device_features
			);
		}
		// There are no virtio-fs specific featurebits yet.
		// TODO: actually check features
		// currently provided features of virtio-fs:
		// 0000000000000000000000000000000100110000000000000000000000000000
		// only accept VIRTIO_F_VERSION_1 for now.

		/*
		// on failure:
		common_cfg.device_status |= 128;
		return ERROR;
		*/
	}

	/// 3.1 VirtIO Device Initialization
	pub fn init(&mut self) {
		// 1.Reset the device.
		self.common_cfg.device_status = 0;

		// 2.Set the ACKNOWLEDGE status bit: the guest OS has notice the device.
		self.common_cfg.device_status |= 1;

		// 3.Set the DRIVER status bit: the guest OS knows how to drive the device.
		self.common_cfg.device_status |= 2;

		// 4.Read device feature bits, and write the subset of feature bits understood by the OS and driver to the device.
		//   During this step the driver MAY read (but MUST NOT write) the device-specific configuration fields to check
		//   that it can support the device before accepting it.
		self.negotiate_features();

		// 5.Set the FEATURES_OK status bit. The driver MUST NOT accept new feature bits after this step.
		self.common_cfg.device_status |= 8;

		// 6.Re-read device status to ensure the FEATURES_OK bit is still set:
		//   otherwise, the device does not support our subset of features and the device is unusable.
		if self.common_cfg.device_status & 8 == 0 {
			error!("Device unset FEATURES_OK, aborting!");
			return;
		}

		// 7.Perform device-specific setup, including discovery of virtqueues for the device, optional per-bus setup,
		//   reading and possibly writing the device’s virtio configuration space, and population of virtqueues.
		self.init_vqs();

		// 8.Set the DRIVER_OK status bit. At this point the device is “live”.
		self.common_cfg.device_status |= 4;
	}
}

impl FuseInterface for VirtioFsDriver<'_> {
	fn send_recv_buffers_blocking (
		&mut self,
		to_host: &[&[u8]], from_host: &[&mut [u8]]
	) -> Result<(), ()>
	{
		if let Some(ref mut vqueues) = self.vqueues {
			vqueues[1].send_blocking(to_host, Some(from_host));
		}
		Ok(())
	}

	/* TODO: make TEST out of this!

	pub fn send_hello(&mut self) {
		// Setup virtio-fs (5.11 in virtio spec @ https://stefanha.github.io/virtio/virtio-fs.html#x1-41500011)
		// 5.11.5 Device Initialization
		// On initialization the driver first discovers the device’s virtqueues.
		// The FUSE session is started by sending a FUSE_INIT request as defined by the FUSE protocol on one request virtqueue.
		// All virtqueues provide access to the same FUSE session and therefore only one FUSE_INIT request is required
		// regardless of the number of available virtqueues.

		// 5.11.6 Device Operation
		// TODO: send a simple getdents as test
		// Send FUSE_INIT
		// example, see https://elixir.bootlin.com/linux/latest/source/fs/fuse/inode.c#L973 (fuse_send_init)
		// https://github.com/torvalds/linux/blob/76f6777c9cc04efe8036b1d2aa76e618c1631cc6/fs/fuse/dev.c#L1190 <<- max_write



		/*if let Some(ref mut vqueues) = self.vqueues {
			// TODO: this is a stack based buffer.. maybe not the best idea for DMA, but PoC works with this
			let outbuf = [0;128];
			vqueues[1].send_blocking(&[
				// fuse_in_header
				96,0,0,0, // pub len: u32, // 96 for all bytes!. Yet still returns: "elem 0 too short for out_header" "elem 0 no reply sent"
				26,0,0,0, // pub opcode: u32,
				1,0,0,0,0,0,0,0, // pub unique: u64,
				1,0,0,0,0,0,0,0, // pub nodeid: u64,
				0,0,0,0, // pub uid: u32,
				0,0,0,0, // pub gid: u32,
				1,0,0,0, // pub pid: u32,
				0,0,0,0, // pub padding: u32,
				// fuse_init_in
				7,0,0,0, // major
				31,0,0,0, // minor
				0,0,0,0, // max_readahead
				0,0,0,0, // flags
				/*// fuse_out_header
				0,0,0,0, // pub len: u32,
				0,0,0,0, // pub error: i32,
				0,0,0,0,0,0,0,0, // pub unique: u64,
				// fuse_init_out
				0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,*/
			], Some(&outbuf));
			// TODO: Answer is already here. This is not guaranteed by any spec, we should wait until it appears in used ring!
			info!("{:?}", &outbuf[..]);
		}*/
	}
	*/
}

fn get_device_config(adapter: &pci::PciAdapter) -> Result<&'static mut virtio_fs_config, ()> {
	let cap = virtio::find_virtiocap(adapter, VIRTIO_PCI_CAP_DEVICE_CFG, None).unwrap();
	let (cap_device_raw, _length) = virtio::map_cap(adapter, &cap, true)?;

	Ok(unsafe { &mut *(cap_device_raw as *mut virtio_fs_config) })
}

pub fn create_virtiofs_driver(
	adapter: &pci::PciAdapter,
) -> Result<Rc<RefCell<VirtioFsDriver<'static>>>, ()> {
	// Scan capabilities to get common config, which we need to reset the device and get basic info.
	// also see https://elixir.bootlin.com/linux/latest/source/drivers/virtio/virtio_pci_modern.c#L581 (virtio_pci_modern_probe)
	// Read status register
	let bus = adapter.bus;
	let device = adapter.device;
	let status = pci::read_config(bus, device, pci::PCI_COMMAND_REGISTER) >> 16;

	// non-legacy virtio device always specifies capability list, so it can tell us in which bar we find the virtio-config-space
	if status & pci::PCI_STATUS_CAPABILITIES_LIST == 0 {
		error!("Found virtio device without capability list. Likely legacy-device! Aborting.");
		return Err(());
	}

	// get common config mapped, cast to virtio_pci_common_cfg
	let common_cfg = if let Some(c) = virtio::get_common_config(adapter).ok() {
		c
	} else {
		error!("Could not find VIRTIO_PCI_CAP_COMMON_CFG. Aborting!");
		return Err(());
	};

	// get device config mapped, cast to virtio_fs_config
	let device_cfg = if let Some(d) = get_device_config(adapter).ok() {
		d
	} else {
		error!("Could not find VIRTIO_PCI_CAP_DEVICE_CFG. Aborting!");
		return Err(());
	};

	let notify_cfg = if let Some(n) = virtio::get_notify_config(adapter).ok() {
		n
	} else {
		error!("Could not find VIRTIO_PCI_CAP_NOTIFY_CFG. Aborting!");
		return Err(());
	};

	let shm_cfg = virtio::get_shm_config(adapter, VIRTIO_FS_SHMCAP_ID_CACHE).ok();

	if let Some(shm) = &shm_cfg {
		info!("Found Cache! Using DAX! {:?}", shm);
	} else {
		info!("No Cache found, not using DAX!");
	}

	// TODO: also load the other 2 cap types (?).

	// Instanciate driver on heap, so it outlives this function
	let drv = Rc::new(RefCell::new(VirtioFsDriver {
		common_cfg,
		device_cfg,
		notify_cfg,
		shm_cfg,
		vqueues: None,
	}));

	trace!("Driver before init: {:?}", drv);
	drv.borrow_mut().init();
	trace!("Driver after init: {:?}", drv);

	// Instanciate global fuse object
	let mut fuse = if let Some(shm) = &drv.borrow().shm_cfg {
		info!("Found Cache! Using DAX! {:?}", shm);
		let dax_allocator = DaxAllocator::new(shm.addr as u64, shm.len);
		Fuse::new_with_dax(drv.clone(), dax_allocator)
	} else {
		info!("No Cache found, not using DAX!");
		Fuse::new(drv.clone())
	};

	// send FUSE_INIT to create session
	fuse.send_init();

	let mut fs = fs::FILESYSTEM.lock();
	let tag = util::c_buf_to_str(&device_cfg.tag);
	info!("Mounting virtio-fs at /{}", tag);
	fs.mount(tag, Box::new(fuse))
		.expect("Mount failed. Duplicate tag?");

	Ok(drv)
}
