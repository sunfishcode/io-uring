//! Submission Queue

use core::fmt::{self, Debug, Display, Formatter};
use core::mem;
use core::sync::atomic;
#[cfg(feature = "std")]
use std::error::Error;

use crate::sys;
use crate::util::{private, unsync_load, Mmap};

use bitflags::bitflags;

pub(crate) struct Inner<E: EntryMarker> {
    pub(crate) head: *const atomic::AtomicU32,
    pub(crate) tail: *const atomic::AtomicU32,
    pub(crate) ring_mask: u32,
    pub(crate) ring_entries: u32,
    pub(crate) flags: *const atomic::AtomicU32,
    dropped: *const atomic::AtomicU32,

    pub(crate) sqes: *mut E,
}

/// An io_uring instance's submission queue. This is used to send I/O requests to the kernel.
pub struct SubmissionQueue<'a, E: EntryMarker = Entry> {
    head: u32,
    tail: u32,
    queue: &'a Inner<E>,
}

/// A submission queue entry (SQE), representing a request for an I/O operation.
///
/// This is implemented for [`Entry`] and [`Entry128`].
pub trait EntryMarker: Clone + Debug + From<Entry> + private::Sealed {
    const BUILD_FLAGS: sys::IoringSetupFlags;
}

/// A 64-byte submission queue entry (SQE), representing a request for an I/O operation.
///
/// These can be created via opcodes in [`opcode`](crate::opcode).
#[repr(C)]
pub struct Entry(pub(crate) sys::io_uring_sqe);

/// A 128-byte submission queue entry (SQE), representing a request for an I/O operation.
///
/// These can be created via opcodes in [`opcode`](crate::opcode).
#[repr(C)]
#[derive(Clone)]
pub struct Entry128(pub(crate) Entry, pub(crate) [u8; 64]);

#[test]
fn test_entry_sizes() {
    assert_eq!(mem::size_of::<Entry>(), 64);
    assert_eq!(mem::size_of::<Entry128>(), 128);
}

bitflags! {
    /// Submission flags
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
    pub struct Flags: u8 {
        /// When this flag is specified,
        /// `fd` is an index into the files array registered with the io_uring instance.
        #[doc(hidden)]
        const FIXED_FILE =  sys::IoringSqeFlags::FIXED_FILE.bits();

        /// When this flag is specified,
        /// the SQE will not be started before previously submitted SQEs have completed,
        /// and new SQEs will not be started before this one completes.
        const IO_DRAIN =  sys::IoringSqeFlags::IO_DRAIN.bits();

        /// When this flag is specified,
        /// it forms a link with the next SQE in the submission ring.
        /// That next SQE will not be started before this one completes.
        const IO_LINK =  sys::IoringSqeFlags::IO_LINK.bits();

        /// Like [`IO_LINK`](Self::IO_LINK), but it doesn’t sever regardless of the completion
        /// result.
        const IO_HARDLINK =  sys::IoringSqeFlags::IO_HARDLINK.bits();

        /// Normal operation for io_uring is to try and issue an sqe as non-blocking first,
        /// and if that fails, execute it in an async manner.
        ///
        /// To support more efficient overlapped operation of requests
        /// that the application knows/assumes will always (or most of the time) block,
        /// the application can ask for an sqe to be issued async from the start.
        const ASYNC =  sys::IoringSqeFlags::ASYNC.bits();

        /// Conceptually the kernel holds a set of buffers organized into groups. When you issue a
        /// request with this flag and set `buf_group` to a valid buffer group ID (e.g.
        /// [`buf_group` on `Read`](crate::opcode::Read::buf_group)) then once the file descriptor
        /// becomes ready the kernel will try to take a buffer from the group.
        ///
        /// If there are no buffers in the group, your request will fail with `-ENOBUFS`. Otherwise,
        /// the corresponding [`cqueue::Entry::flags`](crate::cqueue::Entry::flags) will contain the
        /// chosen buffer ID, encoded with:
        ///
        /// ```text
        /// (buffer_id << IORING_CQE_BUFFER_SHIFT) | IORING_CQE_F_BUFFER
        /// ```
        ///
        /// You can use [`buffer_select`](crate::cqueue::buffer_select) to take the buffer ID.
        ///
        /// The buffer will then be removed from the group and won't be usable by other requests
        /// anymore.
        ///
        /// You can provide new buffers in a group with
        /// [`ProvideBuffers`](crate::opcode::ProvideBuffers).
        ///
        /// See also [the LWN thread on automatic buffer
        /// selection](https://lwn.net/Articles/815491/).
        const BUFFER_SELECT =  sys::IoringSqeFlags::BUFFER_SELECT.bits();

        /// Don't post CQE if request succeeded.
        const SKIP_SUCCESS =  sys::IoringSqeFlags::CQE_SKIP_SUCCESS.bits();
    }
}

impl<E: EntryMarker> Inner<E> {
    #[rustfmt::skip]
    pub(crate) unsafe fn new(
        sq_mmap: &Mmap,
        sqe_mmap: &Mmap,
        p: &sys::io_uring_params,
    ) -> Self {
        let head         = sq_mmap.offset(p.sq_off.head        ) as *const atomic::AtomicU32;
        let tail         = sq_mmap.offset(p.sq_off.tail        ) as *const atomic::AtomicU32;
        let ring_mask    = sq_mmap.offset(p.sq_off.ring_mask   ).cast::<u32>().read();
        let ring_entries = sq_mmap.offset(p.sq_off.ring_entries).cast::<u32>().read();
        let flags        = sq_mmap.offset(p.sq_off.flags       ) as *const atomic::AtomicU32;
        let dropped      = sq_mmap.offset(p.sq_off.dropped     ) as *const atomic::AtomicU32;
        let array        = sq_mmap.offset(p.sq_off.array       ) as *mut u32;

        let sqes         = sqe_mmap.as_mut_ptr() as *mut E;

        // To keep it simple, map it directly to `sqes`.
        for i in 0..ring_entries {
            array.add(i as usize).write_volatile(i);
        }

        Self {
            head,
            tail,
            ring_mask,
            ring_entries,
            flags,
            dropped,
            sqes,
        }
    }

    #[inline]
    pub(crate) unsafe fn borrow_shared(&self) -> SubmissionQueue<'_, E> {
        SubmissionQueue {
            head: (*self.head).load(atomic::Ordering::Acquire),
            tail: unsync_load(self.tail),
            queue: self,
        }
    }

    #[inline]
    pub(crate) fn borrow(&mut self) -> SubmissionQueue<'_, E> {
        unsafe { self.borrow_shared() }
    }
}

impl<E: EntryMarker> SubmissionQueue<'_, E> {
    /// Synchronize this type with the real submission queue.
    ///
    /// This will flush any entries added by [`push`](Self::push) or
    /// [`push_multiple`](Self::push_multiple) and will update the queue's length if the kernel has
    /// consumed some entries in the meantime.
    #[inline]
    pub fn sync(&mut self) {
        unsafe {
            (*self.queue.tail).store(self.tail, atomic::Ordering::Release);
            self.head = (*self.queue.head).load(atomic::Ordering::Acquire);
        }
    }

    /// When [`is_setup_sqpoll`](crate::Parameters::is_setup_sqpoll) is set, whether the kernel
    /// threads has gone to sleep and requires a system call to wake it up.
    #[inline]
    pub fn need_wakeup(&self) -> bool {
        unsafe {
            sys::IoringSqFlags::from_bits_retain(
                (*self.queue.flags).load(atomic::Ordering::Acquire),
            )
            .contains(sys::IoringSqFlags::NEED_WAKEUP)
        }
    }

    /// The number of invalid submission queue entries that have been encountered in the ring
    /// buffer.
    pub fn dropped(&self) -> u32 {
        unsafe { (*self.queue.dropped).load(atomic::Ordering::Acquire) }
    }

    /// Returns `true` if the completion queue ring is overflown.
    pub fn cq_overflow(&self) -> bool {
        unsafe {
            sys::IoringSqFlags::from_bits_retain(
                (*self.queue.flags).load(atomic::Ordering::Acquire),
            )
            .contains(sys::IoringSqFlags::CQ_OVERFLOW)
        }
    }

    /// Returns `true` if completions are pending that should be processed. Only relevant when used
    /// in conjuction with the `setup_taskrun_flag` function. Available since 5.19.
    pub fn taskrun(&self) -> bool {
        unsafe {
            (*self.queue.flags).load(atomic::Ordering::Acquire) & sys::IoringSqFlags::TASKRUN.bits()
                != 0
        }
    }

    /// Get the total number of entries in the submission queue ring buffer.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.queue.ring_entries as usize
    }

    /// Get the number of submission queue events in the ring buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.tail.wrapping_sub(self.head) as usize
    }

    /// Returns `true` if the submission queue ring buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns `true` if the submission queue ring buffer has reached capacity, and no more events
    /// can be added before the kernel consumes some.
    #[inline]
    pub fn is_full(&self) -> bool {
        self.len() == self.capacity()
    }

    /// Attempts to push an entry into the queue.
    /// If the queue is full, an error is returned.
    ///
    /// # Safety
    ///
    /// Developers must ensure that parameters of the entry (such as buffer) are valid and will
    /// be valid for the entire duration of the operation, otherwise it may cause memory problems.
    #[inline]
    pub unsafe fn push(&mut self, entry: &E) -> Result<(), PushError> {
        if !self.is_full() {
            self.push_unchecked(entry);
            Ok(())
        } else {
            Err(PushError)
        }
    }

    /// Attempts to push several entries into the queue.
    /// If the queue does not have space for all of the entries, an error is returned.
    ///
    /// # Safety
    ///
    /// Developers must ensure that parameters of all the entries (such as buffer) are valid and
    /// will be valid for the entire duration of the operation, otherwise it may cause memory
    /// problems.
    #[inline]
    pub unsafe fn push_multiple(&mut self, entries: &[E]) -> Result<(), PushError> {
        if self.capacity() - self.len() < entries.len() {
            return Err(PushError);
        }

        for entry in entries {
            self.push_unchecked(entry);
        }

        Ok(())
    }

    #[inline]
    unsafe fn push_unchecked(&mut self, entry: &E) {
        *self
            .queue
            .sqes
            .add((self.tail & self.queue.ring_mask) as usize) = entry.clone();
        self.tail = self.tail.wrapping_add(1);
    }
}

impl<E: EntryMarker> Drop for SubmissionQueue<'_, E> {
    #[inline]
    fn drop(&mut self) {
        unsafe { &*self.queue.tail }.store(self.tail, atomic::Ordering::Release);
    }
}

impl Entry {
    /// Set the submission event's [flags](Flags).
    #[inline]
    pub fn flags(mut self, flags: Flags) -> Entry {
        self.0.flags |= sys::IoringSqeFlags::from_bits(flags.bits()).unwrap();
        self
    }

    /// Set the user data as a `u64`. This is an application-supplied value
    /// that will be passed straight through into the
    /// [completion queue entry](crate::cqueue::Entry::user_data).
    #[inline]
    pub fn user_data(mut self, user_data: u64) -> Entry {
        self.0.user_data = sys::io_uring_user_data::from_u64(user_data);
        self
    }

    /// Set the user data as a pointer. This is an application-supplied value
    /// that will be passed straight through into the
    /// [completion queue entry](crate::cqueue::Entry::user_data).
    #[inline]
    pub fn user_data_ptr(mut self, user_data: *mut libc::c_void) -> Entry {
        self.0.user_data = sys::io_uring_user_data::from_ptr(user_data);
        self
    }

    /// Get the previously application-supplied user data as a `u64`.
    #[inline]
    pub fn get_user_data(&self) -> u64 {
        self.0.user_data.u64_()
    }

    /// Get the previously application-supplied user data as a pointer.
    #[inline]
    pub fn get_user_data_ptr(&self) -> *mut libc::c_void {
        self.0.user_data.ptr()
    }

    /// Set the personality of this event. You can obtain a personality using
    /// [`Submitter::register_personality`](crate::Submitter::register_personality).
    pub fn personality(mut self, personality: u16) -> Entry {
        self.0.personality = personality;
        self
    }
}

impl private::Sealed for Entry {}

impl EntryMarker for Entry {
    const BUILD_FLAGS: sys::IoringSetupFlags = sys::IoringSetupFlags::empty();
}

impl Clone for Entry {
    fn clone(&self) -> Entry {
        // io_uring_sqe doesn't implement Clone due to the 'cmd' incomplete array field.
        Entry(unsafe { mem::transmute_copy(&self.0) })
    }
}

impl Debug for Entry {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("op_code", &self.0.opcode)
            .field("flags", &self.0.flags)
            .field("user_data", &self.0.user_data)
            .finish()
    }
}

impl Entry128 {
    /// Set the submission event's [flags](Flags).
    #[inline]
    pub fn flags(mut self, flags: Flags) -> Entry128 {
        self.0 .0.flags |= sys::IoringSqeFlags::from_bits(flags.bits()).unwrap();
        self
    }

    /// Set the user data. This is an application-supplied value that will be passed straight
    /// through into the [completion queue entry](crate::cqueue::Entry::user_data).
    #[inline]
    pub fn user_data(mut self, user_data: u64) -> Entry128 {
        self.0 .0.user_data = sys::io_uring_user_data::from_u64(user_data);
        self
    }

    /// Set the user data. This is an application-supplied value that will be passed straight
    /// through into the [completion queue entry](crate::cqueue::Entry::user_data).
    #[inline]
    pub fn user_data_ptr(mut self, user_data: *mut libc::c_void) -> Entry128 {
        self.0 .0.user_data = sys::io_uring_user_data::from_ptr(user_data);
        self
    }

    /// Set the personality of this event. You can obtain a personality using
    /// [`Submitter::register_personality`](crate::Submitter::register_personality).
    #[inline]
    pub fn personality(mut self, personality: u16) -> Entry128 {
        self.0 .0.personality = personality;
        self
    }
}

impl private::Sealed for Entry128 {}

impl EntryMarker for Entry128 {
    const BUILD_FLAGS: sys::IoringSetupFlags = sys::IoringSetupFlags::SQE128;
}

impl From<Entry> for Entry128 {
    fn from(entry: Entry) -> Entry128 {
        Entry128(entry, [0u8; 64])
    }
}

impl Debug for Entry128 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry128")
            .field("op_code", &self.0 .0.opcode)
            .field("flags", &self.0 .0.flags)
            .field("user_data", &self.0 .0.user_data)
            .finish()
    }
}

/// An error pushing to the submission queue due to it being full.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PushError;

impl Display for PushError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("submission queue is full")
    }
}

#[cfg(feature = "std")]
impl Error for PushError {}

impl<E: EntryMarker> Debug for SubmissionQueue<'_, E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_list();
        let mut pos = self.head;
        while pos != self.tail {
            let entry: &E = unsafe { &*self.queue.sqes.add((pos & self.queue.ring_mask) as usize) };
            d.entry(&entry);
            pos = pos.wrapping_add(1);
        }
        d.finish()
    }
}
