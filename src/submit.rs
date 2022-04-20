use std::os::unix::io::RawFd;
use std::sync::atomic;
use std::{io, ptr};

use crate::register::{execute, Probe};
use crate::sys;
use crate::util::{cast_ptr, Fd};
use crate::Parameters;

#[cfg(feature = "unstable")]
use crate::register::Restriction;

#[cfg(feature = "unstable")]
use crate::types;

/// Interface for submitting submission queue events in an io_uring instance to the kernel for
/// executing and registering files or buffers with the instance.
///
/// io_uring supports both directly performing I/O on buffers and file descriptors and registering
/// them beforehand. Registering is slow, but it makes performing the actual I/O much faster.
pub struct Submitter<'a> {
    fd: &'a Fd,
    params: &'a Parameters,

    sq_head: *const atomic::AtomicU32,
    sq_tail: *const atomic::AtomicU32,
    sq_flags: *const atomic::AtomicU32,
}

impl<'a> Submitter<'a> {
    #[inline]
    pub(crate) const fn new(
        fd: &'a Fd,
        params: &'a Parameters,
        sq_head: *const atomic::AtomicU32,
        sq_tail: *const atomic::AtomicU32,
        sq_flags: *const atomic::AtomicU32,
    ) -> Submitter<'a> {
        Submitter {
            fd,
            params,
            sq_head,
            sq_tail,
            sq_flags,
        }
    }

    #[inline]
    fn sq_len(&self) -> usize {
        unsafe {
            let head = (*self.sq_head).load(atomic::Ordering::Acquire);
            let tail = (*self.sq_tail).load(atomic::Ordering::Acquire);

            tail.wrapping_sub(head) as usize
        }
    }

    /// Whether the kernel thread has gone to sleep because it waited for too long without
    /// submission queue entries.
    #[inline]
    fn sq_need_wakeup(&self) -> bool {
        unsafe {
            (*self.sq_flags).load(atomic::Ordering::Acquire)
                & sys::IoringSqFlags::NEED_WAKEUP.bits()
                != 0
        }
    }

    /// Initiate and/or complete asynchronous I/O. This is a low-level wrapper around
    /// `io_uring_enter` - see `man io_uring_enter` (or [its online
    /// version](https://manpages.debian.org/unstable/liburing-dev/io_uring_enter.2.en.html) for
    /// more details.
    ///
    /// You will probably want to use a more high-level API such as
    /// [`submit`](Self::submit) or [`submit_and_wait`](Self::submit_and_wait).
    ///
    /// # Safety
    ///
    /// This provides a raw interface so developer must ensure that parameters are correct.
    pub unsafe fn enter<T: Sized>(
        &self,
        to_submit: u32,
        min_complete: u32,
        flag: sys::IoringEnterFlags,
        arg: Option<&T>,
    ) -> io::Result<usize> {
        let arg = arg
            .map(|arg| cast_ptr(arg) as *const _)
            .unwrap_or_else(ptr::null);
        let size = std::mem::size_of::<T>();
        let result = sys::io_uring_enter(self.fd, to_submit, min_complete, flag, arg, size)?;
        Ok(result as _)
    }

    /// Submit all queued submission queue events to the kernel.
    #[inline]
    pub fn submit(&self) -> io::Result<usize> {
        self.submit_and_wait(0)
    }

    /// Submit all queued submission queue events to the kernel and wait for at least `want`
    /// completion events to complete.
    pub fn submit_and_wait(&self, want: usize) -> io::Result<usize> {
        let len = self.sq_len();
        let mut flags = sys::IoringEnterFlags::empty();

        if want > 0 || self.params.is_setup_iopoll() {
            flags |= sys::IoringEnterFlags::GETEVENTS;
        }

        if self.params.is_setup_sqpoll() {
            if self.sq_need_wakeup() {
                flags |= sys::IoringEnterFlags::SQ_WAKEUP;
            } else if want == 0 {
                // The kernel thread is polling and hasn't fallen asleep, so we don't need to tell
                // it to process events or wake it up
                return Ok(len);
            }
        }

        unsafe { self.enter::<libc::sigset_t>(len as _, want as _, flags, None) }
    }

    #[cfg(feature = "unstable")]
    pub fn submit_with_args(
        &self,
        want: usize,
        args: &types::SubmitArgs<'_, '_>,
    ) -> io::Result<usize> {
        let len = self.sq_len();
        let mut flags = sys::IoringEnterFlags::EXT_ARG;

        if want > 0 {
            flags |= sys::IoringEnterFlags::GETEVENTS;
        }

        if self.params.is_setup_sqpoll() {
            if self.sq_need_wakeup() {
                flags |= sys::IoringEnterFlags::SQ_WAKEUP;
            } else if want == 0 {
                // The kernel thread is polling and hasn't fallen asleep, so we don't need to tell
                // it to process events or wake it up
                return Ok(len);
            }
        }

        unsafe { self.enter(len as _, want as _, flags, Some(&args.args)) }
    }

    /// Wait for the submission queue to have free entries.
    ///
    /// Requires the `unstable` feature.
    #[cfg(feature = "unstable")]
    pub fn squeue_wait(&self) -> io::Result<usize> {
        unsafe { self.enter::<libc::sigset_t>(0, 0, sys::IoringEnterFlags::SQ_WAIT, None) }
    }

    /// Register in-memory user buffers for I/O with the kernel. You can use these buffers with the
    /// [`ReadFixed`](crate::opcode::ReadFixed) and [`WriteFixed`](crate::opcode::WriteFixed)
    /// operations.
    pub fn register_buffers(&self, bufs: &[libc::iovec]) -> io::Result<()> {
        execute(
            self.fd,
            sys::IoringRegisterOp::RegisterBuffers,
            bufs.as_ptr() as *const _,
            bufs.len() as _,
        )
    }

    /// Register files for I/O. You can use the registered files with
    /// [`Fixed`](crate::types::Fixed).
    ///
    /// Each fd may be -1, in which case it is considered "sparse", and can be filled in later with
    /// [`register_files_update`](Self::register_files_update).
    ///
    /// Note that this will wait for the ring to idle; it will only return once all active requests
    /// are complete. Use [`register_files_update`](Self::register_files_update) to avoid this.
    pub fn register_files(&self, fds: &[RawFd]) -> io::Result<()> {
        execute(
            self.fd,
            sys::IoringRegisterOp::RegisterFiles,
            fds.as_ptr() as *const _,
            fds.len() as _,
        )
    }

    /// This operation replaces existing files in the registered file set with new ones,
    /// either turning a sparse entry (one where fd is equal to -1) into a real one, removing an existing entry (new one is set to -1),
    /// or replacing an existing entry with a new existing entry. The `offset` parameter specifies
    /// the offset into the list of registered files at which to start updating files.
    ///
    /// You can also perform this asynchronously with the
    /// [`FilesUpdate`](crate::opcode::FilesUpdate) opcode.
    pub fn register_files_update(&self, offset: u32, fds: &[RawFd]) -> io::Result<()> {
        let fu = sys::io_uring_files_update {
            offset,
            resv: 0,
            fds: fds.as_ptr() as _,
        };
        let fu = cast_ptr::<sys::io_uring_files_update>(&fu);
        execute(
            self.fd,
            sys::IoringRegisterOp::RegisterFilesUpdate,
            fu as *const _,
            fds.len() as _,
        )?;
        Ok(())
    }

    /// Register an eventfd created by [`eventfd`](libc::eventfd) with the io_uring instance.
    pub fn register_eventfd(&self, eventfd: RawFd) -> io::Result<()> {
        execute(
            self.fd,
            sys::IoringRegisterOp::RegisterEventfd,
            cast_ptr::<RawFd>(&eventfd) as *const _,
            1,
        )
    }

    /// This works just like [`register_eventfd`](Self::register_eventfd), except notifications are
    /// only posted for events that complete in an async manner, so requests that complete
    /// immediately will not cause a notification.
    pub fn register_eventfd_async(&self, eventfd: RawFd) -> io::Result<()> {
        execute(
            self.fd,
            sys::IoringRegisterOp::RegisterEventfdAsync,
            cast_ptr::<RawFd>(&eventfd) as *const _,
            1,
        )
    }

    /// Fill in the given [`Probe`] with information about the opcodes supported by io_uring on the
    /// running kernel.
    ///
    /// # Examples
    ///
    // This is marked no_run as it is only available from Linux 5.6+, however the latest Ubuntu (on
    // which CI runs) only has Linux 5.4.
    /// ```no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let io_uring = io_uring::IoUring::new(1)?;
    /// let mut probe = io_uring::Probe::new();
    /// io_uring.submitter().register_probe(&mut probe)?;
    ///
    /// if probe.is_supported(io_uring::opcode::Read::CODE) {
    ///     println!("Reading is supported!");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn register_probe(&self, probe: &mut Probe) -> io::Result<()> {
        execute(
            self.fd,
            sys::IoringRegisterOp::RegisterProbe,
            probe.as_mut_ptr() as *const _,
            Probe::COUNT as _,
        )
    }

    /// Register credentials of the running application with io_uring, and get an id associated with
    /// these credentials. This ID can then be [passed](crate::squeue::Entry::personality) into
    /// submission queue entries to issue the request with this process' credentials.
    ///
    /// By default, if [`Parameters::is_feature_cur_personality`] is set then requests will use the
    /// credentials of the task that called [`Submitter::enter`], otherwise they will use the
    /// credentials of the task that originally registered the io_uring.
    ///
    /// [`Parameters::is_feature_cur_personality`]: crate::Parameters::is_feature_cur_personality
    pub fn register_personality(&self) -> io::Result<()> {
        execute(
            self.fd,
            sys::IoringRegisterOp::RegisterPersonality,
            ptr::null(),
            0,
        )?;
        Ok(())
    }

    /// Unregister all previously registered buffers.
    ///
    /// You do not need to explicitly call this before dropping the [`IoUring`](crate::IoUring), as
    /// it will be cleaned up by the kernel automatically.
    pub fn unregister_buffers(&self) -> io::Result<()> {
        execute(
            self.fd,
            sys::IoringRegisterOp::UnregisterBuffers,
            ptr::null(),
            0,
        )
    }

    /// Unregister all previously registered files.
    ///
    /// You do not need to explicitly call this before dropping the [`IoUring`](crate::IoUring), as
    /// it will be cleaned up by the kernel automatically.
    pub fn unregister_files(&self) -> io::Result<()> {
        execute(
            self.fd,
            sys::IoringRegisterOp::UnregisterFiles,
            ptr::null(),
            0,
        )
    }

    /// Unregister an eventfd file descriptor to stop notifications.
    pub fn unregister_eventfd(&self) -> io::Result<()> {
        execute(
            self.fd,
            sys::IoringRegisterOp::UnregisterEventfd,
            ptr::null(),
            0,
        )
    }

    /// Unregister a previously registered personality.
    pub fn unregister_personality(&self, personality: u16) -> io::Result<()> {
        execute(
            self.fd,
            sys::IoringRegisterOp::UnregisterPersonality,
            ptr::null(),
            personality as _,
        )
    }

    /// Permanently install a feature allowlist. Once this has been called, attempting to perform
    /// an operation not on the allowlist will fail with `-EACCES`.
    ///
    /// This can only be called once, to prevent untrusted code from removing restrictions.
    ///
    /// Requires the `unstable` feature.
    #[cfg(feature = "unstable")]
    pub fn register_restrictions(&self, res: &mut [Restriction]) -> io::Result<()> {
        execute(
            self.fd,
            sys::IoringRegisterOp::RegisterRestrictions,
            res.as_mut_ptr().cast(),
            res.len() as _,
        )
    }

    /// Enable the rings of the io_uring instance if they have been disabled with
    /// [`setup_r_disabled`](crate::Builder::setup_r_disabled).
    ///
    /// Requires the `unstable` feature.
    #[cfg(feature = "unstable")]
    pub fn register_enable_rings(&self) -> io::Result<()> {
        execute(
            self.fd,
            sys::IoringRegisterOp::RegisterEnableRings,
            ptr::null(),
            0,
        )
    }

    /// Get and/or set the limit for number of io_uring worker threads per NUMA
    /// node. `max[0]` holds the limit for bounded workers, which process I/O
    /// operations expected to be bound in time, that is I/O on regular files or
    /// block devices. While `max[1]` holds the limit for unbounded workers,
    /// which carry out I/O operations that can never complete, for instance I/O
    /// on sockets. Passing `0` does not change the current limit. Returns
    /// previous limits on success.
    ///
    /// Requires the `unstable` feature.
    #[cfg(feature = "unstable")]
    pub fn register_iowq_max_workers(&self, max: &mut [u32; 2]) -> io::Result<()> {
        execute(
            self.fd,
            sys::IoringRegisterOp::RegisterIowqMaxWorkers,
            max.as_mut_ptr().cast(),
            max.len() as _,
        )
    }
}
