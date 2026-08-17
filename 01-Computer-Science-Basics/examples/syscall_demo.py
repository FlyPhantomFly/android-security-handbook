#!/usr/bin/env python3
# =============================================================================
# syscall_demo.py — file descriptors, fork/exec, pipes and signals, live
# Chapter 01 — Computer Science Basics
# =============================================================================
#
# WHAT THIS PROGRAM DEMONSTRATES
#
#   Python normally hides the operating system behind friendly objects: you
#   call open("x.txt") and get a file object with .read() and .write(). This
#   program deliberately refuses that abstraction and uses the os module, which
#   is a thin wrapper over the real POSIX system calls. Everything you see here
#   maps one-to-one onto a syscall that an Android app makes thousands of times
#   a second:
#
#     os.open()   -> openat(2)      os.fork()    -> clone(2)
#     os.read()   -> read(2)        os.execvp()  -> execve(2)
#     os.write()  -> write(2)       os.waitpid() -> wait4(2)
#     os.close()  -> close(2)       os.kill()    -> kill(2)
#     os.pipe()   -> pipe2(2)       signal()     -> rt_sigaction(2)
#     os.lseek()  -> lseek(2)       os.dup2()    -> dup3(2)
#
#   The five ideas it makes concrete:
#
#     1. A file descriptor is a small integer index into a per-process table
#        the KERNEL owns. 0/1/2 are stdin/stdout/stderr by convention only.
#     2. fork() returns twice: once in the parent with the child's PID, and
#        once in the child with 0. Both processes then run the same code from
#        the same point with separate, copy-on-write address spaces.
#     3. exec() does not create a process. It REPLACES the current process
#        image, keeping the PID and (unless CLOEXEC is set) the descriptors.
#     4. A pipe is a pair of descriptors joined by a kernel buffer, and it is
#        the oldest and simplest form of inter-process communication.
#     5. A signal is an asynchronous interrupt delivered to a process. The
#        handler runs at a point the program did not choose.
#
# WHY YOU SHOULD CARE (Android security)
#
#   Every Android app process is created by fork() from zygote. Every Binder
#   transaction is an ioctl() on a file descriptor pointing at /dev/binder.
#   Every SharedPreferences write is an openat() plus write() plus fsync().
#   Every native crash is a signal (SIGSEGV, SIGABRT) caught by a handler that
#   writes a tombstone. Root detection and Frida detection are open() and
#   read() against /proc. Anti-debugging uses ptrace(), which is a syscall.
#   When you run `strace -f -p <pid>` against an app, THIS is the vocabulary
#   the output is written in, and none of it is readable until you have made
#   the calls yourself.
#
# HOW TO RUN
#
#   Linux / WSL2 / macOS, Python 3.8 or newer, standard library only:
#
#       python3 syscall_demo.py
#
#   On a real Android device, if you have a Python build available (Termux,
#   or a rooted device with a static python pushed to /data/local/tmp):
#
#       adb push syscall_demo.py /data/local/tmp/
#       adb shell "cd /data/local/tmp && ./python3 syscall_demo.py"
#
#   Windows is NOT supported: os.fork() does not exist there. Use WSL2.
#
# WHAT TO WATCH IN strace
#
#   Run it again under strace and read along with the narration:
#
#       strace -f -e trace=openat,read,write,close,lseek,pipe2,clone,execve,\
# wait4,kill,rt_sigaction,rt_sigreturn -o trace.txt python3 syscall_demo.py
#       less trace.txt
#
#   -f is essential: without it strace follows only the parent and the child's
#   syscalls disappear. Then look for these specific things:
#
#     * openat(AT_FDCWD, "/tmp/...", O_RDWR|O_CREAT|O_TRUNC, 0600) = 3
#       The RETURN VALUE 3 is the file descriptor. It is 3 because 0, 1 and 2
#       were already taken. Note that Python's high-level open() would produce
#       the same syscall -- the abstraction is thin.
#
#     * clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|...) = 12345
#       This is fork(). Modern glibc implements fork() via clone(). Android's
#       bionic does the same. The return value in the parent's trace is the
#       child PID; the child's own trace shows the call returning 0.
#
#     * execve("/bin/echo", ["echo", ...], 0x...) = 0
#       Everything the process was is gone after this line. Subsequent syscalls
#       in that PID belong to a different program.
#
#     * write(4, "...", n) = n  followed by  read(3, "...", 4096) = n
#       The pipe. Descriptor numbers differ between parent and child.
#
#     * rt_sigaction(SIGUSR1, {sa_handler=0x...}, ...) = 0
#       Installing the handler. Later, --- SIGUSR1 {si_signo=SIGUSR1,
#       si_code=SI_USER, si_pid=...} --- marks actual delivery, and
#       rt_sigreturn() marks the handler returning.
#
#     * A blocking read() shows as read(3, <unfinished ...> until data arrives.
#       That is what "the process is in state S (interruptible sleep)" in
#       /proc/<pid>/status means, from the other side.
#
#   On Android the equivalent is the same tool:
#
#       adb shell strace -f -p $(adb shell pidof com.example.target)
#
#   though you will need root, and the volume is enormous -- always filter with
#   -e trace=... and always redirect to a file.
#
# SEE ALSO
#   labs/lab-02-processes-memory-maps.md — /proc/<pid>/fd, the other half of this
#   ../../02-Linux-Basics/README.md      — the shell view of the same mechanisms
#   ../../25-Binder/README.md            — ioctl() on /dev/binder, Android's IPC
# =============================================================================

import errno
import os
import signal
import sys
import tempfile
import time

# -----------------------------------------------------------------------------
# Narration helpers. Nothing security-relevant here; they just make the output
# readable so the program teaches while it runs.
# -----------------------------------------------------------------------------

WIDTH = 78


def banner(title):
    print()
    print("=" * WIDTH)
    print(f" {title}")
    print("=" * WIDTH)


def step(text):
    print(f"  [{os.getpid():>7}] {text}")


def note(text):
    for line in text.strip().splitlines():
        print(f"           | {line.strip()}")


def require_posix():
    """Refuse to run anywhere fork() does not exist, with a useful message."""
    if not hasattr(os, "fork"):
        print("This program requires POSIX fork(). It cannot run on Windows.")
        print("Use WSL2, a Linux VM, macOS, or an Android device with Termux.")
        sys.exit(1)


# =============================================================================
# SECTION 1 — File descriptors are just integers
# =============================================================================

def demo_file_descriptors():
    banner("SECTION 1 — a file descriptor is a small integer")

    note("""
    The kernel keeps a table of open resources for every process. A file
    descriptor is nothing but an index into that table. It has no meaning
    outside the process that owns it, it is not a pointer, and the kernel
    always hands out the LOWEST unused number.
    """)

    step(f"standard input  is fd {sys.stdin.fileno()}")
    step(f"standard output is fd {sys.stdout.fileno()}")
    step(f"standard error  is fd {sys.stderr.fileno()}")

    # tempfile.mkstemp() itself calls open(2) and hands back a RAW descriptor,
    # which is unusual and exactly what we want here.
    fd, path = tempfile.mkstemp(prefix="syscall_demo_", suffix=".bin")
    step(f"mkstemp() gave us fd {fd} for {path}")
    note("""
    fd is 3 on a normal run: 0, 1 and 2 were already taken, so 3 was the
    lowest free slot. If you had redirected output or opened something else
    first, you would get a different number. Never hardcode a descriptor.
    """)

    # --- write(2) -----------------------------------------------------------
    payload = b"dex\n035\x00" + bytes(range(16))
    written = os.write(fd, payload)
    step(f"os.write(fd={fd}, {len(payload)} bytes) returned {written}")
    note("""
    write(2) returns the number of bytes ACTUALLY written, which may be less
    than you asked for on a socket or a pipe. Ignoring that return value is a
    genuine and common bug: 'short writes' silently truncate data.
    """)

    # --- lseek(2) -----------------------------------------------------------
    pos = os.lseek(fd, 0, os.SEEK_CUR)
    step(f"current file offset after writing: {pos}")
    os.lseek(fd, 0, os.SEEK_SET)
    step("os.lseek(fd, 0, SEEK_SET) — rewound to the start")
    note("""
    The offset lives in the kernel's open-file description, not in your
    process. Two descriptors duplicated with dup() SHARE an offset; two
    descriptors from two separate open() calls do not. That distinction is
    the source of many file-corruption bugs.
    """)

    # --- read(2) ------------------------------------------------------------
    data = os.read(fd, 4096)
    step(f"os.read(fd={fd}, 4096) returned {len(data)} bytes")
    step(f"first 8 bytes as hex : {data[:8].hex(' ')}")
    step(f"first 8 bytes as text: {data[:8]!r}")
    note("""
    Those eight bytes are the real DEX file magic from Lab 01: 64 65 78 0a
    30 33 35 00, meaning 'dex', newline, the ASCII version digits 035, and a
    NUL. read() returning 0 -- not an error, just 0 -- is how end-of-file is
    signalled. read() returning fewer bytes than requested is normal.
    """)

    # --- dup2(2) ------------------------------------------------------------
    dup_fd = os.dup(fd)
    step(f"os.dup(fd={fd}) returned a second descriptor: {dup_fd}")
    note("""
    Both descriptors now refer to the SAME open file, sharing one offset.
    This is the mechanism behind shell redirection: the shell forks, calls
    dup2(logfile_fd, 1) so that descriptor 1 refers to the log file, and only
    then calls execve(). The new program writes to 'stdout' with no idea it
    has been redirected. Android's app_process and logwrapper do the same.
    """)

    # --- /proc/self/fd ------------------------------------------------------
    if os.path.isdir("/proc/self/fd"):
        step("contents of /proc/self/fd (the kernel's view of our table):")
        for name in sorted(os.listdir("/proc/self/fd"), key=lambda s: int(s)):
            try:
                target = os.readlink(f"/proc/self/fd/{name}")
            except OSError as exc:
                target = f"<unreadable: {exc.strerror}>"
            print(f"           |   {name:>3} -> {target}")
        note("""
        This is exactly what you read in Lab 02 with `ls -l /proc/<pid>/fd`.
        For a real Android app the same listing shows /dev/binder, open
        SQLite databases, sockets, ashmem regions and the app's own APK.
        """)
    else:
        note("/proc is not mounted here (macOS), so the table cannot be listed.")

    # --- errno --------------------------------------------------------------
    step("now deliberately provoking an error to show errno")
    try:
        os.read(9999, 16)
    except OSError as exc:
        step(f"os.read(9999, 16) raised OSError: errno={exc.errno} "
             f"({errno.errorcode.get(exc.errno)}) — {exc.strerror}")
    note("""
    Every syscall reports failure the same way: it returns -1 and sets the
    thread-local variable errno. Python turns that into an OSError whose
    .errno attribute is the raw number. EBADF (9) means 'bad file
    descriptor'. Others you will meet constantly on Android: EACCES (13,
    permission denied -- often SELinux), ENOENT (2, no such file), EPERM (1),
    EAGAIN (11, would block), and ECONNREFUSED (111).
    """)

    os.close(dup_fd)
    os.close(fd)
    os.unlink(path)
    step(f"closed fds {fd} and {dup_fd}, unlinked {path}")


# =============================================================================
# SECTION 2 — fork() returns twice
# =============================================================================

def demo_fork():
    banner("SECTION 2 — fork() returns twice, into two processes")

    note("""
    fork() duplicates the calling process. Afterwards there are two processes
    executing the same code at the same instruction, with separate address
    spaces that the kernel shares copy-on-write until one of them writes.
    The ONLY way to tell them apart is the return value: 0 in the child, the
    child's PID in the parent.
    """)

    parent_pid = os.getpid()
    step(f"before fork: I am pid {parent_pid}, my parent is {os.getppid()}")

    shared_variable = "written before fork"

    pid = os.fork()

    if pid == 0:
        # ---------------- child ----------------
        step("fork() returned 0 -> I am the CHILD")
        step(f"my pid is {os.getpid()}, my parent is {os.getppid()}")
        step(f"I inherited shared_variable = {shared_variable!r}")
        shared_variable = "child changed it"
        step(f"I changed it to {shared_variable!r} — the parent will NOT see this")
        # os._exit skips Python's cleanup handlers. In a forked child that is
        # the correct thing to do: running the parent's atexit hooks and
        # flushing its buffers twice causes duplicated output and corruption.
        os._exit(7)

    # ---------------- parent ----------------
    step(f"fork() returned {pid} -> I am the PARENT, my child is pid {pid}")
    wpid, status = os.waitpid(pid, 0)
    step(f"os.waitpid({pid}) returned pid={wpid}, raw status=0x{status:04x}")

    if os.WIFEXITED(status):
        step(f"child exited normally with code {os.WEXITSTATUS(status)}")
    elif os.WIFSIGNALED(status):
        step(f"child was killed by signal {os.WTERMSIG(status)}")

    step(f"my shared_variable is still {shared_variable!r}")
    note("""
    The child's assignment did not touch the parent's memory. Copy-on-write
    means the page was shared read-only until the child wrote to it, at which
    point the kernel gave the child a private copy. This is precisely how
    Android app startup works: zygote has already loaded the whole framework,
    forks, and the child inherits it all for free until it modifies something.
    Every app on the device therefore begins with the same memory layout.

    A process that exits and whose parent has not yet called wait() is a
    ZOMBIE: state Z in ps, still holding a PID and an exit status. If the
    parent dies first, init (pid 1) adopts the orphan and reaps it.
    """)


# =============================================================================
# SECTION 3 — a pipe between parent and child
# =============================================================================

def demo_pipe():
    banner("SECTION 3 — a pipe: two descriptors and a kernel buffer")

    note("""
    os.pipe() returns (read_fd, write_fd). Bytes written to write_fd become
    readable from read_fd. The buffer lives in the kernel, so the two ends can
    belong to different processes -- which is the whole point.

    The discipline that beginners get wrong: EACH process must close the end
    it does not use. If the parent keeps the write end open, the child's read()
    never sees end-of-file and blocks forever, because 'EOF on a pipe' means
    'the last writer closed it'.
    """)

    read_fd, write_fd = os.pipe()
    step(f"os.pipe() gave read_fd={read_fd}, write_fd={write_fd}")

    pid = os.fork()

    if pid == 0:
        # ---------------- child: the writer ----------------
        os.close(read_fd)                       # child will not read
        step(f"CHILD closed the read end (fd {read_fd})")
        for i in range(3):
            message = f"message {i} from child pid {os.getpid()}\n".encode()
            n = os.write(write_fd, message)
            step(f"CHILD wrote {n} bytes")
            time.sleep(0.15)
        os.close(write_fd)                      # this is what produces EOF
        step(f"CHILD closed the write end (fd {write_fd}) — parent will see EOF")
        os._exit(0)

    # ---------------- parent: the reader ----------------
    os.close(write_fd)                          # parent will not write
    step(f"PARENT closed the write end (fd {write_fd})")

    buffered = b""
    while True:
        chunk = os.read(read_fd, 4096)          # blocks until data or EOF
        if not chunk:                           # b"" means EOF, not an error
            step("PARENT: os.read() returned 0 bytes -> EOF, all writers closed")
            break
        step(f"PARENT read {len(chunk)} bytes")
        buffered += chunk

    os.close(read_fd)
    os.waitpid(pid, 0)

    print()
    note("data that crossed the process boundary:")
    for line in buffered.decode().splitlines():
        print(f"           |   {line}")

    note("""
    That is the mechanism behind `ls | grep foo`, behind Java's
    Runtime.exec() and ProcessBuilder, and behind every Android tool that
    shells out and captures output. A pipe carries an unstructured byte
    stream with no message boundaries -- if you need records, you must frame
    them yourself, which is why length-prefixed protocols exist and why the
    endianness of that length prefix matters (Lab 01).

    Android's real IPC does NOT use pipes. Binder was built because pipes
    require two copies of the data and carry no caller identity; Binder does
    one copy and delivers the caller's UID and PID, which is what makes
    permission checks possible at all. See ../../25-Binder/README.md.
    """)


# =============================================================================
# SECTION 4 — exec() replaces the process image
# =============================================================================

def demo_exec():
    banner("SECTION 4 — exec() replaces the running program in place")

    note("""
    exec() does NOT create a process. It keeps the PID, the parent, the open
    descriptors (unless they were opened with O_CLOEXEC), the working
    directory and the credentials, and throws away everything else: the code,
    the heap, the stack, the mappings. The line after a successful execvp()
    NEVER runs.

    fork() + exec() together are how every program on a Unix system is
    started. On Android, zygote forks but deliberately does NOT exec, so the
    child keeps the preloaded framework -- the single most important
    performance decision in the platform, and the reason every app shares a
    memory layout.
    """)

    # Set up a pipe so we can capture the exec'd program's stdout, exactly the
    # way a shell does it.
    read_fd, write_fd = os.pipe()

    pid = os.fork()

    if pid == 0:
        # ---------------- child: becomes another program ----------------
        os.close(read_fd)
        step("CHILD: about to redirect stdout into the pipe with dup2()")
        os.dup2(write_fd, 1)        # descriptor 1 now refers to the pipe
        os.close(write_fd)
        step("CHILD: calling execvp('/bin/echo'). Nothing after this line runs.")
        sys.stdout.flush()
        try:
            os.execvp("echo", ["echo", "Hello from a completely different program,",
                               "running under the SAME pid."])
        except OSError as exc:
            # Only reached if exec FAILED -- for example ENOENT.
            os.write(2, f"execvp failed: {exc}\n".encode())
        os._exit(127)               # 127 is the conventional 'command not found'

    # ---------------- parent ----------------
    os.close(write_fd)
    output = b""
    while True:
        chunk = os.read(read_fd, 4096)
        if not chunk:
            break
        output += chunk
    os.close(read_fd)
    _, status = os.waitpid(pid, 0)

    step(f"PARENT captured {len(output)} bytes from the exec'd program:")
    for line in output.decode(errors="replace").splitlines():
        print(f"           |   {line}")
    step(f"child pid {pid} exited with status {os.WEXITSTATUS(status)}")

    note("""
    Notice that the child's PID never changed, yet the program running under
    it did. In `ps` you would have seen a python3 process turn into an echo
    process. Malware uses exactly this to hide: fork, then exec a benign-looking
    binary, or call prctl(PR_SET_NAME) to relabel itself. The Name field in
    /proc/<pid>/status is not evidence of anything.

    In strace, look for the execve() line. Everything before it belongs to
    Python; everything after it belongs to echo.
    """)


# =============================================================================
# SECTION 5 — signals: asynchronous interrupts
# =============================================================================

# Module-level state the handler can touch. A signal handler must do as little
# as possible: it interrupts the program at an arbitrary instruction, so it may
# only call async-signal-safe functions. Setting a flag is the canonical safe
# action. (Python serialises handlers onto the main thread between bytecodes,
# which makes it safer than C, but the discipline is still worth learning.)
_signals_received = []


def _handler(signum, frame):
    _signals_received.append(signum)
    name = signal.Signals(signum).name
    # print() is not async-signal-safe in C. It is acceptable in Python's
    # handler model and is used here purely for narration.
    print(f"  [{os.getpid():>7}] !! handler ran: caught {name} ({signum})")


def demo_signals():
    banner("SECTION 5 — signals arrive when the program is not expecting them")

    note("""
    A signal is a number delivered asynchronously to a process. The kernel
    suspends whatever the process was doing, runs a handler, and resumes.
    Each signal has a default action if you install no handler: terminate,
    terminate and dump core, stop, or ignore.
    """)

    print()
    print("           | Signal    Num  Default action           Android relevance")
    print("           | -------   ---  ----------------------   ---------------------------")
    print("           | SIGSEGV    11  terminate + core dump    invalid memory access; ART's")
    print("           |                                         handler writes the tombstone")
    print("           | SIGABRT     6  terminate + core dump    abort(); also stack-smash")
    print("           |                                         detection and CHECK() failures")
    print("           | SIGILL      4  terminate + core dump    illegal instruction; seen when")
    print("           |                                         a hook lands mid-instruction")
    print("           | SIGBUS      7  terminate + core dump    misaligned or truncated mmap")
    print("           | SIGKILL     9  terminate, UNCATCHABLE   the low-memory killer, and")
    print("           |                                         `am force-stop`")
    print("           | SIGTERM    15  terminate                polite shutdown request")
    print("           | SIGSTOP    19  stop, UNCATCHABLE        used by debuggers")
    print("           | SIGTRAP     5  terminate + core dump    breakpoints; ptrace uses it")
    print("           | SIGCHLD    17  ignore                   a child changed state")
    print("           | SIGUSR1/2  10/12 terminate              free for the application;")
    print("           |                                         ART uses one for GC signalling")
    print()

    note("""
    SIGKILL and SIGSTOP cannot be caught, blocked or ignored. That is a
    deliberate kernel guarantee: there must always be a way to stop a process.
    It is also why Android's low-memory killer uses SIGKILL -- an app cannot
    refuse to die, which is exactly why onDestroy() is not guaranteed to run.
    """)

    # --- install handlers ---------------------------------------------------
    old_usr1 = signal.signal(signal.SIGUSR1, _handler)
    old_usr2 = signal.signal(signal.SIGUSR2, _handler)
    step("installed handlers for SIGUSR1 and SIGUSR2 (rt_sigaction in strace)")

    # --- send a signal to ourselves ----------------------------------------
    step("sending SIGUSR1 to myself with os.kill(os.getpid(), SIGUSR1)")
    os.kill(os.getpid(), signal.SIGUSR1)
    step("...and control returned here after the handler finished")

    # --- have a child signal the parent ------------------------------------
    step("forking a child that will signal me from another process")
    parent_pid = os.getpid()
    pid = os.fork()
    if pid == 0:
        time.sleep(0.3)
        os.kill(parent_pid, signal.SIGUSR2)
        os._exit(0)

    # signal.pause() sleeps until ANY signal arrives. In strace the parent's
    # syscall shows as pause() or rt_sigsuspend(), and the process state in
    # /proc/<pid>/status is S (interruptible sleep).
    step("calling signal.pause() — sleeping until a signal wakes me")
    signal.pause()
    os.waitpid(pid, 0)

    # --- a timer signal -----------------------------------------------------
    caught_alarm = []

    def alarm_handler(signum, frame):
        caught_alarm.append(signum)
        raise TimeoutError("SIGALRM interrupted a blocking read")

    signal.signal(signal.SIGALRM, alarm_handler)
    r, w = os.pipe()
    step("installing a 1-second SIGALRM and then blocking on read() with no writer")
    signal.alarm(1)
    try:
        os.read(r, 16)          # would block forever; the alarm rescues us
        step("read() returned normally (unexpected)")
    except TimeoutError as exc:
        step(f"read() was interrupted: {exc}")
    except OSError as exc:
        if exc.errno == errno.EINTR:
            step("read() failed with EINTR — 'interrupted system call'")
        else:
            raise
    finally:
        signal.alarm(0)
        os.close(r)
        os.close(w)

    note("""
    A blocking syscall interrupted by a signal returns -1 with errno EINTR
    unless the handler was installed with SA_RESTART. Every robust piece of
    native code must therefore wrap blocking calls in a retry loop. Forgetting
    to do so produces bugs that appear only under load, only on some devices,
    and only sometimes -- the worst kind.
    """)

    # --- signal masks -------------------------------------------------------
    if hasattr(signal, "pthread_sigmask"):
        blocked = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1})
        step("blocked SIGUSR1 with pthread_sigmask(SIG_BLOCK)")
        os.kill(os.getpid(), signal.SIGUSR1)
        step("sent SIGUSR1 while blocked — it is now PENDING, not lost")
        pending = signal.sigpending()
        step(f"signal.sigpending() reports: "
             f"{sorted(signal.Signals(s).name for s in pending)}")
        signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
        step("unblocked — the pending signal is delivered immediately:")
        time.sleep(0.05)
        note("""
        Blocked signals are held, not discarded. Standard signals do not
        queue: ten SIGUSR1s delivered while blocked become one on unblock.
        Real-time signals (SIGRTMIN and above) do queue. This distinction
        matters when you are reasoning about whether an app could have missed
        a notification.
        """)

    step(f"signals caught during this section: "
         f"{[signal.Signals(s).name for s in _signals_received]}")

    signal.signal(signal.SIGUSR1, old_usr1)
    signal.signal(signal.SIGUSR2, old_usr2)


# =============================================================================
# Closing narration
# =============================================================================

def closing():
    banner("Where this shows up on Android")
    note("""
    fork()            zygote forks every app process; the child never execs,
                      which is why all apps share a warm framework image.
    exec()            the shell, `am`, `logwrapper` and native helpers; also
                      the point at which SELinux performs a domain transition.
    file descriptors  /dev/binder for every framework call, SQLite databases,
                      shared_prefs XML, sockets, ashmem and memfd regions. All
                      of them are visible in /proc/<pid>/fd -- see Lab 02.
    pipes             Runtime.exec() output capture; logd's input path.
    signals           SIGSEGV and SIGABRT are caught by debuggerd, which walks
                      the frame chain and writes /data/tombstones/tombstone_NN;
                      SIGKILL from the low-memory killer ends app processes
                      without notice.
    errno             every 'Permission denied' you will ever debug on Android
                      is EACCES or EPERM coming back from one of these calls,
                      usually because of a UID mismatch or an SELinux denial.

    Next steps:
      * Re-run this program under strace -f and match every narration line to
        a syscall line.
      * Do the same against a real app:
            adb shell strace -f -e trace=openat,read,write,ioctl \\
                -p $(adb shell pidof com.example.target)
        and watch the ioctl() calls on /dev/binder scroll past. That is the
        Android framework, seen from below.
      * Read ../../02-Linux-Basics/README.md and ../../25-Binder/README.md.
    """)


def main():
    require_posix()

    print("=" * WIDTH)
    print(" syscall_demo.py — the operating system, without the abstractions")
    print("=" * WIDTH)
    print(f" pid={os.getpid()}  ppid={os.getppid()}  uid={os.getuid()}  "
          f"gid={os.getgid()}")
    print(f" platform={sys.platform}  python={sys.version.split()[0]}")
    print(f" cwd={os.getcwd()}")

    demo_file_descriptors()
    demo_fork()
    demo_pipe()
    demo_exec()
    demo_signals()
    closing()

    print()
    print("=" * WIDTH)
    print(" done")
    print("=" * WIDTH)


if __name__ == "__main__":
    main()
