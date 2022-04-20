//! Operation codes that can be used to construct [`squeue::Entry`](crate::squeue::Entry)s.

#![allow(clippy::new_without_default)]

use std::mem;
use std::os::unix::io::RawFd;

use crate::squeue::Entry;
use crate::sys;
use crate::types::{self, sealed};

macro_rules! assign_fd {
    ( $sqe:ident . fd = $opfd:expr ) => {
        match $opfd {
            sealed::Target::Fd(fd) => $sqe.fd = fd,
            sealed::Target::Fixed(i) => {
                $sqe.fd = i as _;
                $sqe.flags |=
                    sys::IoringSqeFlags::from_bits(crate::squeue::Flags::FIXED_FILE.bits())
                        .unwrap();
            }
        }
    };
}

macro_rules! opcode {
    (@type impl sealed::UseFixed ) => {
        sealed::Target
    };
    (@type impl sealed::UseFd ) => {
        RawFd
    };
    (@type $name:ty ) => {
        $name
    };
    (
        $( #[$outer:meta] )*
        pub struct $name:ident {
            $( #[$new_meta:meta] )*

            $( $field:ident : { $( $tnt:tt )+ } ),*

            $(,)?

            ;;

            $(
                $( #[$opt_meta:meta] )*
                $opt_field:ident : $opt_tname:ty = $default:expr
            ),*

            $(,)?
        }

        pub const CODE = $opcode:expr;

        $( #[$build_meta:meta] )*
        pub fn build($self:ident) -> Entry $build_block:block
    ) => {
        $( #[$outer] )*
        pub struct $name {
            $( $field : opcode!(@type $( $tnt )*), )*
            $( $opt_field : $opt_tname, )*
        }

        impl $name {
            $( #[$new_meta] )*
            #[inline]
            pub fn new($( $field : $( $tnt )* ),*) -> Self {
                $name {
                    $( $field: $field.into(), )*
                    $( $opt_field: $default, )*
                }
            }

            /// The opcode of the operation. This can be passed to
            /// [`Probe::is_supported`](crate::Probe::is_supported) to check if this operation is
            /// supported with the current kernel.
            pub const CODE: sys::IoringOp = $opcode as _;

            $(
                $( #[$opt_meta] )*
                #[inline]
                pub const fn $opt_field(mut self, $opt_field: $opt_tname) -> Self {
                    self.$opt_field = $opt_field;
                    self
                }
            )*

            $( #[$build_meta] )*
            #[inline]
            pub fn build($self) -> Entry $build_block
        }
    }
}

/// inline zeroed to improve codegen
#[inline(always)]
fn sqe_zeroed() -> sys::io_uring_sqe {
    unsafe { std::mem::zeroed() }
}

opcode!(
    /// Do not perform any I/O.
    ///
    /// This is useful for testing the performance of the io_uring implementation itself.
    #[derive(Debug)]
    pub struct Nop { ;; }

    pub const CODE = sys::IoringOp::Nop;

    pub fn build(self) -> Entry {
        let Nop {} = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = -1;
        Entry(sqe)
    }
);

opcode!(
    /// Vectored read, equivalent to `preadv2(2)`.
    #[derive(Debug)]
    pub struct Readv {
        fd: { impl sealed::UseFixed },
        iovec: { *const libc::iovec },
        len: { u32 },
        ;;
        ioprio: u16 = 0,
        offset: libc::off_t = 0,
        /// specified for read operations, contains a bitwise OR of per-I/O flags,
        /// as described in the `preadv2(2)` man page.
        rw_flags: types::RwFlags = types::RwFlags::empty()
    }

    pub const CODE = sys::IoringOp::Readv;

    pub fn build(self) -> Entry {
        let Readv {
            fd,
            iovec, len, offset,
            ioprio, rw_flags
        } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.ioprio = ioprio;
        sqe.addr_or_splice_off_in.addr.ptr = iovec as _;
        sqe.len = len;
        sqe.off_or_addr2.off = offset as _;
        sqe.op_flags.rw_flags = rw_flags;
        Entry(sqe)
    }
);

opcode!(
    /// Vectored write, equivalent to `pwritev2(2)`.
    #[derive(Debug)]
    pub struct Writev {
        fd: { impl sealed::UseFixed },
        iovec: { *const libc::iovec },
        len: { u32 },
        ;;
        ioprio: u16 = 0,
        offset: libc::off_t = 0,
        /// specified for write operations, contains a bitwise OR of per-I/O flags,
        /// as described in the `preadv2(2)` man page.
        rw_flags: types::RwFlags = types::RwFlags::empty()
    }

    pub const CODE = sys::IoringOp::Writev;

    pub fn build(self) -> Entry {
        let Writev {
            fd,
            iovec, len, offset,
            ioprio, rw_flags
        } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.ioprio = ioprio;
        sqe.addr_or_splice_off_in.addr.ptr = iovec as _;
        sqe.len = len;
        sqe.off_or_addr2.off = offset as _;
        sqe.op_flags.rw_flags = rw_flags;
        Entry(sqe)
    }
);

opcode!(
    /// File sync, equivalent to `fsync(2)`.
    ///
    /// Note that, while I/O is initiated in the order in which it appears in the submission queue,
    /// completions are unordered. For example, an application which places a write I/O followed by
    /// an fsync in the submission queue cannot expect the fsync to apply to the write. The two
    /// operations execute in parallel, so the fsync may complete before the write is issued to the
    /// storage. The same is also true for previously issued writes that have not completed prior to
    /// the fsync.
    #[derive(Debug)]
    pub struct Fsync {
        fd: { impl sealed::UseFixed },
        ;;
        /// The `flags` bit mask may contain either 0, for a normal file integrity sync,
        /// or [types::FsyncFlags::DATASYNC] to provide data sync only semantics.
        /// See the descriptions of `O_SYNC` and `O_DSYNC` in the `open(2)` manual page for more information.
        flags: types::FsyncFlags = types::FsyncFlags::empty()
    }

    pub const CODE = sys::IoringOp::Fsync;

    pub fn build(self) -> Entry {
        let Fsync { fd, flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.op_flags.fsync_flags = sys::IoringFsyncFlags::from_bits(flags.bits()).unwrap();
        Entry(sqe)
    }
);

opcode!(
    /// Read from pre-mapped buffers that have been previously registered with
    /// [`Submitter::register_buffers`](crate::Submitter::register_buffers).
    ///
    /// The return values match those documented in the `preadv2(2)` man pages.
    #[derive(Debug)]
    pub struct ReadFixed {
        /// The `buf_index` is an index into an array of fixed buffers,
        /// and is only valid if fixed buffers were registered.
        fd: { impl sealed::UseFixed },
        buf: { *mut u8 },
        len: { u32 },
        buf_index: { u16 },
        ;;
        offset: libc::off_t = 0,
        ioprio: u16 = 0,
        /// specified for read operations, contains a bitwise OR of per-I/O flags,
        /// as described in the `preadv2(2)` man page.
        rw_flags: types::RwFlags = types::RwFlags::empty()
    }

    pub const CODE = sys::IoringOp::ReadFixed;

    pub fn build(self) -> Entry {
        let ReadFixed {
            fd,
            buf, len, offset,
            buf_index,
            ioprio, rw_flags
        } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.ioprio = ioprio;
        sqe.addr_or_splice_off_in.addr.ptr = buf as _;
        sqe.len = len;
        sqe.off_or_addr2.off = offset as _;
        sqe.op_flags.rw_flags = rw_flags;
        sqe.buf.buf_index = buf_index;
        Entry(sqe)
    }
);

opcode!(
    /// Write to pre-mapped buffers that have been previously registered with
    /// [`Submitter::register_buffers`](crate::Submitter::register_buffers).
    ///
    /// The return values match those documented in the `pwritev2(2)` man pages.
    #[derive(Debug)]
    pub struct WriteFixed {
        /// The `buf_index` is an index into an array of fixed buffers,
        /// and is only valid if fixed buffers were registered.
        fd: { impl sealed::UseFixed },
        buf: { *const u8 },
        len: { u32 },
        buf_index: { u16 },
        ;;
        ioprio: u16 = 0,
        offset: libc::off_t = 0,
        /// specified for write operations, contains a bitwise OR of per-I/O flags,
        /// as described in the `preadv2(2)` man page.
        rw_flags: types::RwFlags = types::RwFlags::empty()
    }

    pub const CODE = sys::IoringOp::WriteFixed;

    pub fn build(self) -> Entry {
        let WriteFixed {
            fd,
            buf, len, offset,
            buf_index,
            ioprio, rw_flags
        } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.ioprio = ioprio;
        sqe.addr_or_splice_off_in.addr.ptr = buf as _;
        sqe.len = len;
        sqe.off_or_addr2.off = offset as _;
        sqe.op_flags.rw_flags = rw_flags;
        sqe.buf.buf_index = buf_index;
        Entry(sqe)
    }
);

opcode!(
    /// Poll the specified fd.
    ///
    /// Unlike poll or epoll without `EPOLLONESHOT`, this interface always works in one shot mode.
    /// That is, once the poll operation is completed, it will have to be resubmitted.
    #[derive(Debug)]
    pub struct PollAdd {
        /// The bits that may be set in `flags` are defined in `<poll.h>`,
        /// and documented in `poll(2)`.
        fd: { impl sealed::UseFixed },
        flags: { u32 }
        ;;
    }

    pub const CODE = sys::IoringOp::PollAdd;

    pub fn build(self) -> Entry {
        let PollAdd { fd, flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);

        #[cfg(target_endian = "little")] {
            sqe.op_flags.poll32_events = flags;
        }

        #[cfg(target_endian = "big")] {
            let x = flags << 16;
            let y = flags >> 16;
            let flags = x | y;
            sqe.op_flags.poll32_events = flags;
        }

        Entry(sqe)
    }
);

opcode!(
    /// Remove an existing [poll](PollAdd) request.
    ///
    /// If found, the `result` method of the `cqueue::Entry` will return 0.
    /// If not found, `result` will return `-libc::ENOENT`.
    #[derive(Debug)]
    pub struct PollRemove {
        user_data: { u64 }
        ;;
    }

    pub const CODE = sys::IoringOp::PollRemove;

    pub fn build(self) -> Entry {
        let PollRemove { user_data } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = -1;
        sqe.addr_or_splice_off_in.addr.ptr = user_data as _;
        Entry(sqe)
    }
);

opcode!(
    /// Sync a file segment with disk, equivalent to `sync_file_range(2)`.
    #[derive(Debug)]
    pub struct SyncFileRange {
        fd: { impl sealed::UseFixed },
        len: { u32 },
        ;;
        /// the offset method holds the offset in bytes
        offset: libc::off64_t = 0,
        /// the flags method holds the flags for the command
        flags: u32 = 0
    }

    pub const CODE = sys::IoringOp::SyncFileRange;

    pub fn build(self) -> Entry {
        let SyncFileRange {
            fd,
            len, offset,
            flags
        } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.len = len as _;
        sqe.off_or_addr2.off = offset as _;
        sqe.op_flags.sync_range_flags = flags;
        Entry(sqe)
    }
);

opcode!(
    /// Send a message on a socket, equivalent to `send(2)`.
    ///
    /// fd must be set to the socket file descriptor, addr must contains a pointer to the msghdr
    /// structure, and flags holds the flags associated with the system call.
    #[derive(Debug)]
    pub struct SendMsg {
        fd: { impl sealed::UseFixed },
        msg: { *const libc::msghdr },
        ;;
        ioprio: u16 = 0,
        flags: u32 = 0
    }

    pub const CODE = sys::IoringOp::Sendmsg;

    pub fn build(self) -> Entry {
        let SendMsg { fd, msg, ioprio, flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.ioprio = ioprio;
        sqe.addr_or_splice_off_in.addr.ptr = msg as _;
        sqe.len = 1;
        sqe.op_flags.send_flags = rustix::net::SendFlags::from_bits(flags as _).unwrap();
        Entry(sqe)
    }
);

opcode!(
    /// Receive a message on a socket, equivalent to `recvmsg(2)`.
    ///
    /// See also the description of [`SendMsg`].
    #[derive(Debug)]
    pub struct RecvMsg {
        fd: { impl sealed::UseFixed },
        msg: { *mut libc::msghdr },
        ;;
        ioprio: u16 = 0,
        flags: u32 = 0
    }

    pub const CODE = sys::IoringOp::Recvmsg;

    pub fn build(self) -> Entry {
        let RecvMsg { fd, msg, ioprio, flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.ioprio = ioprio;
        sqe.addr_or_splice_off_in.addr.ptr = msg as _;
        sqe.len = 1;
        sqe.op_flags.recv_flags = rustix::net::RecvFlags::from_bits(flags as _).unwrap();
        Entry(sqe)
    }
);

opcode!(
    /// Register a timeout operation.
    ///
    /// A timeout will trigger a wakeup event on the completion ring for anyone waiting for events.
    /// A timeout condition is met when either the specified timeout expires, or the specified number of events have completed.
    /// Either condition will trigger the event.
    /// The request will complete with `-ETIME` if the timeout got completed through expiration of the timer,
    /// or 0 if the timeout got completed through requests completing on their own.
    /// If the timeout was cancelled before it expired, the request will complete with `-ECANCELED`.
    #[derive(Debug)]
    pub struct Timeout {
        timespec: { *const types::Timespec },
        ;;
        /// `count` may contain a completion event count.
        count: u32 = 0,

        /// `flags` may contain [types::TimeoutFlags::ABS] for an absolute timeout value, or 0 for a relative timeout.
        flags: types::TimeoutFlags = types::TimeoutFlags::empty()
    }

    pub const CODE = sys::IoringOp::Timeout;

    pub fn build(self) -> Entry {
        let Timeout { timespec, count, flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = -1;
        sqe.addr_or_splice_off_in.addr.ptr = timespec as _;
        sqe.len = 1;
        sqe.off_or_addr2.off = count as _;
        sqe.op_flags.timeout_flags = sys::IoringTimeoutFlags::from_bits(flags.bits()).unwrap();
        Entry(sqe)
    }
);

// === 5.5 ===

opcode!(
    /// Attempt to remove an existing [timeout operation](Timeout).
    pub struct TimeoutRemove {
        user_data: { u64 },
        ;;
        flags: types::TimeoutFlags = types::TimeoutFlags::empty()
    }

    pub const CODE = sys::IoringOp::TimeoutRemove;

    pub fn build(self) -> Entry {
        let TimeoutRemove { user_data, flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = -1;
        sqe.addr_or_splice_off_in.addr.ptr = user_data as _;
        sqe.op_flags.timeout_flags = sys::IoringTimeoutFlags::from_bits(flags.bits()).unwrap();
        Entry(sqe)
    }
);

opcode!(
    /// Accept a new connection on a socket, equivalent to `accept4(2)`.
    pub struct Accept {
        fd: { impl sealed::UseFixed },
        addr: { *mut libc::sockaddr },
        addrlen: { *mut libc::socklen_t },
        ;;
        flags: i32 = 0
    }

    pub const CODE = sys::IoringOp::Accept;

    pub fn build(self) -> Entry {
        let Accept { fd, addr, addrlen, flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.addr_or_splice_off_in.addr.ptr = addr as _;
        sqe.off_or_addr2.addr2.ptr = addrlen as _;
        sqe.op_flags.accept_flags = rustix::net::AcceptFlags::from_bits(flags as _).unwrap();
        Entry(sqe)
    }
);

opcode!(
    /// Attempt to cancel an already issued request.
    pub struct AsyncCancel {
        user_data: { u64 }
        ;;

        // TODO flags
    }

    pub const CODE = sys::IoringOp::AsyncCancel;

    pub fn build(self) -> Entry {
        let AsyncCancel { user_data } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = -1;
        sqe.addr_or_splice_off_in.addr.ptr = user_data as _;
        Entry(sqe)
    }
);

opcode!(
    /// This request must be linked with another request through
    /// [`Flags::IO_LINK`](crate::squeue::Flags::IO_LINK) which is described below.
    /// Unlike [`Timeout`], [`LinkTimeout`] acts on the linked request, not the completion queue.
    pub struct LinkTimeout {
        timespec: { *const types::Timespec },
        ;;
        flags: types::TimeoutFlags = types::TimeoutFlags::empty()
    }

    pub const CODE = sys::IoringOp::LinkTimeout;

    pub fn build(self) -> Entry {
        let LinkTimeout { timespec, flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = -1;
        sqe.addr_or_splice_off_in.addr.ptr = timespec as _;
        sqe.len = 1;
        sqe.op_flags.timeout_flags = sys::IoringTimeoutFlags::from_bits(flags.bits()).unwrap();
        Entry(sqe)
    }
);

opcode!(
    /// Connect a socket, equivalent to `connect(2)`.
    pub struct Connect {
        fd: { impl sealed::UseFixed },
        addr: { *const libc::sockaddr },
        addrlen: { libc::socklen_t }
        ;;
    }

    pub const CODE = sys::IoringOp::Connect;

    pub fn build(self) -> Entry {
        let Connect { fd, addr, addrlen } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.addr_or_splice_off_in.addr.ptr = addr as _;
        sqe.off_or_addr2.off = addrlen as _;
        Entry(sqe)
    }
);

// === 5.6 ===

opcode!(
    /// Preallocate or deallocate space to a file, equivalent to `fallocate(2)`.
    pub struct Fallocate {
        fd: { impl sealed::UseFixed },
        len: { libc::off_t },
        ;;
        offset: libc::off_t = 0,
        mode: i32 = 0
    }

    pub const CODE = sys::IoringOp::Fallocate;

    pub fn build(self) -> Entry {
        let Fallocate { fd, len, offset, mode } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.addr_or_splice_off_in.addr.ptr = len as _;
        sqe.len = mode as _;
        sqe.off_or_addr2.off = offset as _;
        Entry(sqe)
    }
);

opcode!(
    /// Open a file, equivalent to `openat(2)`.
    pub struct OpenAt {
        dirfd: { impl sealed::UseFd },
        pathname: { *const libc::c_char },
        ;;
        flags: i32 = 0,
        mode: libc::mode_t = 0
    }

    pub const CODE = sys::IoringOp::Openat;

    pub fn build(self) -> Entry {
        let OpenAt { dirfd, pathname, flags, mode } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = dirfd;
        sqe.addr_or_splice_off_in.addr.ptr = pathname as _;
        sqe.len = mode;
        sqe.op_flags.open_flags = rustix::fs::AtFlags::from_bits(flags as _).unwrap();
        Entry(sqe)
    }
);

opcode!(
    /// Close a file descriptor, equivalent to `close(2)`.
    pub struct Close {
        fd: { impl sealed::UseFd }
        ;;
    }

    pub const CODE = sys::IoringOp::Close;

    pub fn build(self) -> Entry {
        let Close { fd } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = fd;
        Entry(sqe)
    }
);

opcode!(
    /// This command is an alternative to using
    /// [`Submitter::register_files_update`](crate::Submitter::register_files_update) which then
    /// works in an async fashion, like the rest of the io_uring commands.
    pub struct FilesUpdate {
        fds: { *const RawFd },
        len: { u32 },
        ;;
        offset: i32 = 0
    }

    pub const CODE = sys::IoringOp::FilesUpdate;

    pub fn build(self) -> Entry {
        let FilesUpdate { fds, len, offset } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = -1;
        sqe.addr_or_splice_off_in.addr.ptr = fds as _;
        sqe.len = len;
        sqe.off_or_addr2.off = offset as _;
        Entry(sqe)
    }
);

opcode!(
    /// Get file status, equivalent to `statx(2)`.
    pub struct Statx {
        dirfd: { impl sealed::UseFd },
        pathname: { *const libc::c_char },
        statxbuf: { *mut types::statx },
        ;;
        flags: i32 = 0,
        mask: u32 = 0
    }

    pub const CODE = sys::IoringOp::Statx;

    pub fn build(self) -> Entry {
        let Statx {
            dirfd, pathname, statxbuf,
            flags, mask
        } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = dirfd;
        sqe.addr_or_splice_off_in.addr.ptr = pathname as _;
        sqe.len = mask;
        sqe.off_or_addr2.off = statxbuf as _;
        sqe.op_flags.statx_flags = rustix::fs::AtFlags::from_bits(flags as _).unwrap();
        Entry(sqe)
    }
);

opcode!(
    /// Issue the equivalent of a `pread(2)` or `pwrite(2)` system call
    ///
    /// * `fd` is the file descriptor to be operated on,
    /// * `addr` contains the buffer in question,
    /// * `len` contains the length of the IO operation,
    ///
    /// These are non-vectored versions of the `IORING_OP_READV` and `IORING_OP_WRITEV` opcodes.
    /// See also `read(2)` and `write(2)` for the general description of the related system call.
    ///
    /// Available since 5.6.
    pub struct Read {
        fd: { impl sealed::UseFixed },
        buf: { *mut u8 },
        len: { u32 },
        ;;
        /// `offset` contains the read or write offset.
        ///
        /// If `fd` does not refer to a seekable file, `offset` must be set to zero.
        /// If `offsett` is set to `-1`, the offset will use (and advance) the file position,
        /// like the `read(2)` and `write(2)` system calls.
        offset: libc::off_t = 0,
        ioprio: u16 = 0,
        rw_flags: types::RwFlags = types::RwFlags::empty(),
        buf_group: u16 = 0
    }

    pub const CODE = sys::IoringOp::Read;

    pub fn build(self) -> Entry {
        let Read {
            fd,
            buf, len, offset,
            ioprio, rw_flags,
            buf_group
        } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.ioprio = ioprio;
        sqe.addr_or_splice_off_in.addr.ptr = buf as _;
        sqe.len = len;
        sqe.off_or_addr2.off = offset as _;
        sqe.op_flags.rw_flags = rw_flags;
        sqe.buf.buf_group = buf_group;
        Entry(sqe)
    }
);

opcode!(
    /// Issue the equivalent of a `pread(2)` or `pwrite(2)` system call
    ///
    /// * `fd` is the file descriptor to be operated on,
    /// * `addr` contains the buffer in question,
    /// * `len` contains the length of the IO operation,
    ///
    /// These are non-vectored versions of the `IORING_OP_READV` and `IORING_OP_WRITEV` opcodes.
    /// See also `read(2)` and `write(2)` for the general description of the related system call.
    ///
    /// Available since 5.6.
    pub struct Write {
        fd: { impl sealed::UseFixed },
        buf: { *const u8 },
        len: { u32 },
        ;;
        /// `offset` contains the read or write offset.
        ///
        /// If `fd` does not refer to a seekable file, `offset` must be set to zero.
        /// If `offsett` is set to `-1`, the offset will use (and advance) the file position,
        /// like the `read(2)` and `write(2)` system calls.
        offset: libc::off_t = 0,
        ioprio: u16 = 0,
        rw_flags: types::RwFlags = types::RwFlags::empty()
    }

    pub const CODE = sys::IoringOp::Write;

    pub fn build(self) -> Entry {
        let Write {
            fd,
            buf, len, offset,
            ioprio, rw_flags
        } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.ioprio = ioprio;
        sqe.addr_or_splice_off_in.addr.ptr = buf as _;
        sqe.len = len;
        sqe.off_or_addr2.off = offset as _;
        sqe.op_flags.rw_flags = rw_flags;
        Entry(sqe)
    }
);

opcode!(
    /// Predeclare an access pattern for file data, equivalent to `posix_fadvise(2)`.
    pub struct Fadvise {
        fd: { impl sealed::UseFixed },
        len: { libc::off_t },
        advice: { rustix::fs::Advice },
        ;;
        offset: libc::off_t = 0,
    }

    pub const CODE = sys::IoringOp::Fadvise;

    pub fn build(self) -> Entry {
        let Fadvise { fd, len, advice, offset } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.len = len as _;
        sqe.off_or_addr2.off = offset as _;
        sqe.op_flags.fadvise_advice = advice;
        Entry(sqe)
    }
);

opcode!(
    /// Give advice about use of memory, equivalent to `madvise(2)`.
    pub struct Madvise {
        addr: { *const libc::c_void },
        len: { libc::off_t },
        advice: { rustix::fs::Advice },
        ;;
    }

    pub const CODE = sys::IoringOp::Madvise;

    pub fn build(self) -> Entry {
        let Madvise { addr, len, advice } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = -1;
        sqe.addr_or_splice_off_in.addr.ptr = addr as _;
        sqe.len = len as _;
        sqe.op_flags.fadvise_advice = advice as _;
        Entry(sqe)
    }
);

opcode!(
    /// Send a message on a socket, equivalent to `send(2)`.
    pub struct Send {
        fd: { impl sealed::UseFixed },
        buf: { *const u8 },
        len: { u32 },
        ;;
        flags: i32 = 0
    }

    pub const CODE = sys::IoringOp::Send;

    pub fn build(self) -> Entry {
        let Send { fd, buf, len, flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.addr_or_splice_off_in.addr.ptr = buf as _;
        sqe.len = len;
        sqe.op_flags.send_flags = rustix::net::SendFlags::from_bits(flags as _).unwrap();
        Entry(sqe)
    }
);

opcode!(
    /// Receive a message from a socket, equivalent to `recv(2)`.
    pub struct Recv {
        fd: { impl sealed::UseFixed },
        buf: { *mut u8 },
        len: { u32 },
        ;;
        flags: i32 = 0,
        buf_group: u16 = 0
    }

    pub const CODE = sys::IoringOp::Recv;

    pub fn build(self) -> Entry {
        let Recv { fd, buf, len, flags, buf_group } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.addr_or_splice_off_in.addr.ptr = buf as _;
        sqe.len = len;
        sqe.op_flags.recv_flags = rustix::net::RecvFlags::from_bits(flags as _).unwrap();
        sqe.buf.buf_group = buf_group;
        Entry(sqe)
    }
);

opcode!(
    /// Open a file, equivalent to `openat2(2)`.
    pub struct OpenAt2 {
        dirfd: { impl sealed::UseFd },
        pathname: { *const libc::c_char },
        how: { *const types::OpenHow }
        ;;
    }

    pub const CODE = sys::IoringOp::Openat2;

    pub fn build(self) -> Entry {
        let OpenAt2 { dirfd, pathname, how } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = dirfd;
        sqe.addr_or_splice_off_in.addr.ptr = pathname as _;
        sqe.len = mem::size_of::<sys::open_how>() as _;
        sqe.off_or_addr2.off = how as _;
        Entry(sqe)
    }
);

opcode!(
    /// Modify an epoll file descriptor, equivalent to `epoll_ctl(2)`.
    pub struct EpollCtl {
        epfd: { impl sealed::UseFixed },
        fd: { impl sealed::UseFd },
        op: { i32 },
        ev: { *const types::epoll_event },
        ;;
    }

    pub const CODE = sys::IoringOp::EpollCtl;

    pub fn build(self) -> Entry {
        let EpollCtl { epfd, fd, op, ev } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = epfd);
        sqe.addr_or_splice_off_in.addr.ptr = ev as _;
        sqe.len = op as _;
        sqe.off_or_addr2.off = fd as _;
        Entry(sqe)
    }
);

// === 5.7 ===

opcode!(
    /// Splice data to/from a pipe, equivalent to `splice(2)`.
    ///
    /// if `fd_in` refers to a pipe, `off_in` must be `-1`;
    /// The description of `off_in` also applied to `off_out`.
    pub struct Splice {
        fd_in: { impl sealed::UseFixed },
        off_in: { i64 },
        fd_out: { impl sealed::UseFixed },
        off_out: { i64 },
        len: { u32 },
        ;;
        /// see man `splice(2)` for description of flags.
        flags: u32 = 0
    }

    pub const CODE = sys::IoringOp::Splice;

    pub fn build(self) -> Entry {
        let Splice { fd_in, off_in, fd_out, off_out, len, mut flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd_out);
        sqe.len = len;
        sqe.off_or_addr2.off = off_out as _;

        sqe.splice_fd_in_or_file_index.splice_fd_in = match fd_in {
            sealed::Target::Fd(fd) => fd,
            sealed::Target::Fixed(i) => {
                flags |= sys::SpliceFlags::FD_IN_FIXED.bits();
                i as _
            }
        };

        sqe.addr_or_splice_off_in.splice_off_in = off_in as _;
        sqe.op_flags.splice_flags = sys::SpliceFlags::from_bits(flags).unwrap();
        Entry(sqe)
    }
);

#[cfg(feature = "unstable")]
opcode!(
    /// Register `nbufs` buffers that each have the length `len` with ids starting from `big` in the
    /// group `bgid` that can be used for any request. See
    /// [`BUFFER_SELECT`](crate::squeue::Flags::BUFFER_SELECT) for more info.
    ///
    /// Requires the `unstable` feature.
    pub struct ProvideBuffers {
        addr: { *mut u8 },
        len: { i32 },
        nbufs: { u16 },
        bgid: { u16 },
        bid: { u16 }
        ;;
    }

    pub const CODE = sys::IoringOp::ProvideBuffers;

    pub fn build(self) -> Entry {
        let ProvideBuffers { addr, len, nbufs, bgid, bid } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = nbufs as _;
        sqe.addr_or_splice_off_in.addr.ptr = addr as _;
        sqe.len = len as _;
        sqe.off_or_addr2.off = bid as _;
        sqe.buf.buf_group = bgid;
        Entry(sqe)
    }
);

#[cfg(feature = "unstable")]
opcode!(
    /// Remove some number of buffers from a buffer group. See
    /// [`BUFFER_SELECT`](crate::squeue::Flags::BUFFER_SELECT) for more info.
    ///
    /// Requires the `unstable` feature.
    pub struct RemoveBuffers {
        nbufs: { u16 },
        bgid: { u16 }
        ;;
    }

    pub const CODE = sys::IoringOp::RemoveBuffers;

    pub fn build(self) -> Entry {
        let RemoveBuffers { nbufs, bgid } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = nbufs as _;
        sqe.buf.buf_group = bgid;
        Entry(sqe)
    }
);

// === 5.8 ===

#[cfg(feature = "unstable")]
opcode!(
    /// Duplicate pipe content, equivalent to `tee(2)`.
    ///
    /// Requires the `unstable` feature.
    pub struct Tee {
        fd_in: { impl sealed::UseFixed },
        fd_out: { impl sealed::UseFixed },
        len: { u32 }
        ;;
        flags: u32 = 0
    }

    pub const CODE = sys::IoringOp::Tee;

    pub fn build(self) -> Entry {
        let Tee { fd_in, fd_out, len, mut flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;

        assign_fd!(sqe.fd = fd_out);
        sqe.len = len;

        sqe.splice_fd_in_or_file_index.splice_fd_in = match fd_in {
            sealed::Target::Fd(fd) => fd,
            sealed::Target::Fixed(i) => {
                flags |= sys::SpliceFlags::FD_IN_FIXED.bits();
                i as _
            }
        };

        sqe.op_flags.splice_flags = sys::SpliceFlags::from_bits(flags).unwrap();

        Entry(sqe)
    }
);

// === 5.11 ===

#[cfg(feature = "unstable")]
opcode!(
    pub struct Shutdown {
        fd: { impl sealed::UseFixed },
        how: { i32 },
        ;;
    }

    pub const CODE = sys::IoringOp::Shutdown;

    pub fn build(self) -> Entry {
        let Shutdown { fd, how } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.len = how as _;
        Entry(sqe)
    }
);

#[cfg(feature = "unstable")]
opcode!(
    pub struct RenameAt {
        olddirfd: { impl sealed::UseFd },
        oldpath: { *const libc::c_char },
        newdirfd: { impl sealed::UseFd },
        newpath: { *const libc::c_char },
        ;;
        flags: u32 = 0
    }

    pub const CODE = sys::IoringOp::Renameat;

    pub fn build(self) -> Entry {
        let RenameAt {
            olddirfd, oldpath,
            newdirfd, newpath,
            flags
        } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = olddirfd;
        sqe.addr_or_splice_off_in.addr.ptr = oldpath as _;
        sqe.len = newdirfd as _;
        sqe.off_or_addr2.off = newpath as _;
        sqe.op_flags.rename_flags = rustix::fs::RenameFlags::from_bits(flags).unwrap();
        Entry(sqe)
    }
);

#[cfg(feature = "unstable")]
opcode!(
    pub struct UnlinkAt {
        dirfd: { impl sealed::UseFd },
        pathname: { *const libc::c_char },
        ;;
        flags: i32 = 0
    }

    pub const CODE = sys::IoringOp::Unlinkat;

    pub fn build(self) -> Entry {
        let UnlinkAt { dirfd, pathname, flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = dirfd;
        sqe.addr_or_splice_off_in.addr.ptr = pathname as _;
        sqe.op_flags.unlink_flags = rustix::fs::AtFlags::from_bits(flags as _).unwrap();
        Entry(sqe)
    }
);

// === 5.15 ===

#[cfg(feature = "unstable")]
opcode!(
    /// Make a directory, equivalent to `mkdirat2(2)`.
    ///
    /// Requires the `unstable` feature.
    pub struct MkDirAt {
        dirfd: { impl sealed::UseFd },
        pathname: { *const libc::c_char },
        ;;
        mode: libc::mode_t = 0
    }

    pub const CODE = sys::IoringOp::Mkdirat;

    pub fn build(self) -> Entry {
        let MkDirAt { dirfd, pathname, mode } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = dirfd;
        sqe.addr_or_splice_off_in.addr.ptr = pathname as _;
        sqe.len = mode;
        Entry(sqe)
    }
);

#[cfg(feature = "unstable")]
opcode!(
    /// Create a symlink, equivalent to `symlinkat2(2)`.
    ///
    /// Requires the `unstable` feature.
    pub struct SymlinkAt {
        newdirfd: { impl sealed::UseFd },
        target: { *const libc::c_char },
        linkpath: { *const libc::c_char },
        ;;
    }

    pub const CODE = sys::IoringOp::Symlinkat;

    pub fn build(self) -> Entry {
        let SymlinkAt { newdirfd, target, linkpath } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = newdirfd;
        sqe.addr_or_splice_off_in.addr.ptr = target as _;
        sqe.off_or_addr2.addr2.ptr = linkpath as _;
        Entry(sqe)
    }
);

#[cfg(feature = "unstable")]
opcode!(
    /// Create a hard link, equivalent to `linkat2(2)`.
    ///
    /// Requires the `unstable` feature.
    pub struct LinkAt {
        olddirfd: { impl sealed::UseFd },
        oldpath: { *const libc::c_char },
        newdirfd: { impl sealed::UseFd },
        newpath: { *const libc::c_char },
        ;;
        flags: i32 = 0
    }

    pub const CODE = sys::IoringOp::Linkat;

    pub fn build(self) -> Entry {
        let LinkAt { olddirfd, oldpath, newdirfd, newpath, flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = olddirfd as _;
        sqe.addr_or_splice_off_in.addr.ptr = oldpath as _;
        sqe.len = newdirfd as _;
        sqe.off_or_addr2.addr2.ptr = newpath as _;
        sqe.op_flags.hardlink_flags = rustix::fs::AtFlags::from_bits(flags as _).unwrap();
        Entry(sqe)
    }
);
