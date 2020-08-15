use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

pub static FUSE_DAX_MEM_RANGE_SZ: u64 = 512 * 4096; // 512 pages == 2MiB, same as linux kernel

/// Very simple slab allocator for fuse dax cache
pub struct DaxAllocator {
	free_stack: Vec<Rc<RefCell<Slab>>>,
}

impl DaxAllocator {
	pub fn new(start: u64, size: u64) -> Self {
		debug!("Creating Fuse Dax Allocator at {:x}, {:x}", start, size);
		let count = size / FUSE_DAX_MEM_RANGE_SZ;
		let ptr = start as *mut u8;
		let free_stack = (0..count)
			.map(|i| {
				Rc::new(RefCell::new(Slab {
					addr: unsafe { ptr.add((i * FUSE_DAX_MEM_RANGE_SZ) as usize) },
					moffset: i * FUSE_DAX_MEM_RANGE_SZ,
				}))
			})
			.collect();
		Self { free_stack }
	}

	fn allocate(&mut self) -> Result<Rc<RefCell<Slab>>, ()> {
		self.free_stack.pop().ok_or(())
	}

	fn free(&mut self, buf: Rc<RefCell<Slab>>) {
		self.free_stack.push(buf);
	}
}

/// Single slab, allocated by DaxAllocator
#[derive(Debug, Copy, Clone)]
struct Slab {
	addr: *mut u8,
	moffset: u64,
}
/// Single cache entry for fuse dax cache. Has a memory region (slab) and offset into file
#[derive(Debug, Clone)]
pub struct CacheEntry {
	slab: Rc<RefCell<Slab>>,
	file_offset: usize,
}

impl CacheEntry {
	pub fn as_buf(&mut self, file_offset: usize) -> &mut [u8] {
		let buf = unsafe {
			core::slice::from_raw_parts_mut(self.slab.borrow().addr, FUSE_DAX_MEM_RANGE_SZ as usize)
		};
		&mut buf[(file_offset - self.file_offset)..]
	}

	pub fn get_moffset(&self) -> u64 {
		//info!("{:x}", self.slab.borrow().moffset);
		self.slab.borrow().moffset
	}
}

/// Cache for a single file. Stores fileoffset <-> allocated cache mappings
pub struct FuseDaxCache {
	entries: BTreeMap<u64, CacheEntry>,
	allocator: Rc<RefCell<DaxAllocator>>,
}

impl FuseDaxCache {
	pub fn new(allocator: Rc<RefCell<DaxAllocator>>) -> Self {
		Self {
			entries: BTreeMap::new(),
			allocator,
		}
	}

	/// Looks up if offset is currently in slab cache, returns buffer starting at offset if it is
	pub fn get_cached(&mut self, offset: u64) -> Option<CacheEntry> {
		let start = align_down!(offset, FUSE_DAX_MEM_RANGE_SZ);
		//let start_off = offset - start;
		//.map(|e| &mut e.as_buf()[start_off..])
		self.entries.get_mut(&start).map(|e| e.clone())
	}

	/// Allocates a new buffer for caching a file from file_offset. Always of size FUSE_DAX_MEM_RANGE_SZ (512 pages)
	pub fn alloc_cache(&mut self, file_offset: usize) -> Result<CacheEntry, ()> {
		/*if align_down!(file_offset, FUSE_DAX_MEM_RANGE_SZ) != file_offset {
			warn!("Could not allocate unaligned DAX slab!");
			return Err(());
		}*/
		let file_offset = align_down!(file_offset as u64, FUSE_DAX_MEM_RANGE_SZ);

		let slab = self.allocator.borrow_mut().allocate()?;
		{
			trace!("Alloc'd slab for offset {} at {:p} [{:x}]", file_offset, slab.borrow().addr, slab.borrow().moffset);
		}
		let entry = CacheEntry { slab, file_offset: file_offset as usize };
		self.entries.insert(file_offset as u64, entry.clone());
		Ok(entry)
	}

	/// Iterates over all cached entries an calls do_op(file_offset, buffer) on each.
	pub fn iterate_run(&mut self, mut do_op: impl FnMut(&u64, &CacheEntry)) {
		for (addr, buf) in self.entries.iter() {
			do_op(addr, buf);
		}
	}

	/// Gives all allocated cache slabs back to allocator.
	pub fn free(&mut self) {
		// BTreeMap has no drain -> Create new one and swap, then use into_iter()
		let mut entries = BTreeMap::new();
		core::mem::swap(&mut entries, &mut self.entries);

		let mut alloc = self.allocator.borrow_mut();
		for (_addr, buf) in entries.into_iter() {
			alloc.free(buf.slab);
		}
	}
}
