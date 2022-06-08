use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::sync::atomic;
use std::{io, ptr};
use rustix::mm::{ProtFlags, MapFlags, Advice};
use rustix::io::OwnedFd;

/// A region of memory mapped using `mmap(2)`.
pub struct Mmap {
    addr: ptr::NonNull<libc::c_void>,
    len: usize,
}

impl Mmap {
    /// Map `len` bytes starting from the offset `offset` in the file descriptor `fd` into memory.
    pub fn new(fd: &Fd, offset: u64, len: usize) -> io::Result<Mmap> {
        unsafe {
            let addr = rustix::mm::mmap(
                ptr::null_mut(),
                len,
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::SHARED | MapFlags::POPULATE,
                fd,
                offset,
            )?;
            // here, `mmap` will never return null
            let addr = ptr::NonNull::new_unchecked(addr);
            Ok(Mmap { addr, len })
        }
    }

    /// Do not make the stored memory accessible by child processes after a `fork`.
    pub fn dontfork(&self) -> io::Result<()> {
        unsafe {
            rustix::mm::madvise(self.addr.as_ptr(), self.len, Advice::LinuxDontFork)?;
        }
        Ok(())
    }

    /// Get a pointer to the memory.
    #[inline]
    pub fn as_mut_ptr(&self) -> *mut libc::c_void {
        self.addr.as_ptr()
    }

    /// Get a pointer to the data at the given offset.
    #[inline]
    pub unsafe fn offset(&self, offset: u32) -> *mut libc::c_void {
        self.as_mut_ptr().add(offset as usize)
    }
}

impl Drop for Mmap {
    fn drop(&mut self) {
        unsafe {
            rustix::mm::munmap(self.addr.as_ptr(), self.len).unwrap();
        }
    }
}

/// An owned file descriptor.
pub struct Fd(pub OwnedFd);

impl AsRawFd for Fd {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl rustix::fd::AsFd for Fd {
    #[inline]
    fn as_fd(&self) -> rustix::fd::BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl IntoRawFd for Fd {
    #[inline]
    fn into_raw_fd(self) -> RawFd {
        let fd = self.0.into_raw_fd();
        fd
    }
}

impl FromRawFd for Fd {
    #[inline]
    unsafe fn from_raw_fd(fd: RawFd) -> Fd {
        Self(OwnedFd::from_raw_fd(fd))
    }
}

impl rustix::fd::FromFd for Fd {
    #[inline]
    fn from_fd(fd: rustix::fd::OwnedFd) -> Self {
        Self(OwnedFd::from_fd(fd))
    }
}

#[inline(always)]
pub unsafe fn unsync_load(u: *const atomic::AtomicU32) -> u32 {
    *u.cast::<u32>()
}

#[inline]
pub const fn cast_ptr<T>(n: &T) -> *const T {
    n
}
