use crate::synch::semaphore::Semaphore;
use core::cell::UnsafeCell;
use core::fmt;
use core::mem;
use core::ops::{Deref, DerefMut};
use core::ptr;

/// MUTEX based on STDLIB, but MODIFIED to work in the kernel! Might be subtily broken!
/// Since the Poison feature is removed, the API is different!
pub struct Mutex<T: ?Sized> {
	inner: Semaphore,
	data: UnsafeCell<T>,
}

// these are the only places where `T: Send` matters; all other
// functionality works fine on a single thread.
unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}

#[must_use = "if unused the Mutex will immediately unlock"]
pub struct MutexGuard<'a, T: ?Sized + 'a> {
	lock: &'a Mutex<T>,
}

impl<T: ?Sized> !Send for MutexGuard<'_, T> {}
unsafe impl<T: ?Sized + Sync> Sync for MutexGuard<'_, T> {}

impl<T> Mutex<T> {
	pub const fn new(t: T) -> Mutex<T> {
		Mutex {
			inner: Semaphore::new(1),
			data: UnsafeCell::new(t),
		}
	}
}

impl<T: ?Sized> Mutex<T> {
	pub fn lock(&self) -> MutexGuard<'_, T> {
		unsafe {
			self.inner.acquire(None);
			MutexGuard::new(self)
		}
	}

	pub fn try_lock(&self) -> Result<MutexGuard<'_, T>, ()> {
		unsafe {
			if self.inner.try_acquire() {
				Ok(MutexGuard::new(self))
			} else {
				Err(())
			}
		}
	}

	#[allow(dead_code)]
	pub fn into_inner(self) -> T
	where
		T: Sized,
	{
		// We know statically that there are no outstanding references to
		// `self` so there's no need to lock the inner mutex.
		//
		// To get the inner value, we'd like to call `data.into_inner()`,
		// but because `Mutex` impl-s `Drop`, we can't move out of it, so
		// we'll have to destructure it manually instead.
		unsafe {
			// Like `let Mutex { inner, data } = self`.
			let (inner, data) = {
				let Mutex {
					ref inner,
					ref data,
				} = self;
				(ptr::read(inner), ptr::read(data))
			};
			mem::forget(self);
			//inner.destroy(); // Keep in sync with the `Drop` impl.
			drop(inner);

			data.into_inner()
		}
	}

	#[allow(dead_code)]
	pub fn get_mut(&mut self) -> &mut T {
		// We know statically that there are no other references to `self`, so
		// there's no need to lock the inner mutex.
		unsafe { &mut *self.data.get() }
	}
}

impl<T: ?Sized + Default> Default for Mutex<T> {
	fn default() -> Mutex<T> {
		Mutex::new(Default::default())
	}
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for Mutex<T> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self.try_lock() {
			Ok(guard) => f.debug_struct("Mutex").field("data", &&*guard).finish(),
			Err(()) => {
				struct LockedPlaceholder;
				impl fmt::Debug for LockedPlaceholder {
					fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
						f.write_str("<locked>")
					}
				}

				f.debug_struct("Mutex")
					.field("data", &LockedPlaceholder)
					.finish()
			}
		}
	}
}

impl<'mutex, T: ?Sized> MutexGuard<'mutex, T> {
	unsafe fn new(lock: &'mutex Mutex<T>) -> MutexGuard<'mutex, T> {
		MutexGuard { lock }
	}
}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
	type Target = T;

	fn deref(&self) -> &T {
		unsafe { &*self.lock.data.get() }
	}
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
	fn deref_mut(&mut self) -> &mut T {
		unsafe { &mut *self.lock.data.get() }
	}
}

impl<T: ?Sized> Drop for MutexGuard<'_, T> {
	#[inline]
	fn drop(&mut self) {
		self.lock.inner.release();
	}
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for MutexGuard<'_, T> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Debug::fmt(&**self, f)
	}
}

impl<T: ?Sized + fmt::Display> fmt::Display for MutexGuard<'_, T> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		(**self).fmt(f)
	}
}
