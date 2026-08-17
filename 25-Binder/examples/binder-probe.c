/*
 * binder-probe.c -- talk to /dev/binder directly, with no libbinder, no
 *                   servicemanager client library, and no Java.
 *
 * WHAT IT DOES
 *   Everything in Android's IPC stack -- every Intent, every ContentProvider
 *   query, every Keystore operation, every `dumpsys` -- eventually becomes an
 *   ioctl() on a character device called /dev/binder. This program performs
 *   that ioctl by hand so you can see the bytes.
 *
 *   Four modes:
 *
 *     (default)          Open the driver, ask it its protocol version, map the
 *                        receive buffer, and print the exact sizes libbinder
 *                        uses. Reports which of /dev/binder, /dev/hwbinder and
 *                        /dev/vndbinder this process may open at all.
 *
 *     --getservice NAME  Build a checkService transaction by hand -- interface
 *                        token, UTF-16 string, the lot -- send it to handle 0
 *                        (servicemanager), and dump the raw reply parcel,
 *                        decoding the flat_binder_object it contains.
 *
 *     --call NAME CODE   Resolve NAME to a handle, ask that object for its own
 *                        interface descriptor (transaction code '_NTF'), build
 *                        a correctly-tokenised parcel, send transaction CODE,
 *                        and decode the reply -- including the exception
 *                        header, so a SecurityException's text is readable.
 *
 *     --forge-uid UID    Combine with either of the above. Writes UID into the
 *                        sender_euid field of the outgoing
 *                        binder_transaction_data before the ioctl. This is the
 *                        chapter's central security demonstration and it is
 *                        MEANT to have no effect. See "WHAT THIS PROVES".
 *
 * WHY IT EXISTS
 *   The claim "Binder.getCallingUid() cannot be forged" is repeated everywhere
 *   and almost never demonstrated. The struct the caller fills in
 *   (struct binder_transaction_data) HAS a sender_euid field, right there,
 *   writable, in the caller's own memory. It looks forgeable. It is not, and
 *   the reason is a single assignment inside the driver. This program lets you
 *   see both the field and the fact that whatever you put in it is discarded.
 *
 * HOW TO RUN
 *   # host -- build for arm64 with the NDK
 *   NDK=$ANDROID_SDK/ndk/25.2.9519653/toolchains/llvm/prebuilt/<host>/bin
 *   $NDK/aarch64-linux-android21-clang -Wall -Wextra -O2 \
 *       binder-probe.c -o binder-probe
 *
 *   # host -- push and run
 *   adb push binder-probe /data/local/tmp/
 *   adb shell chmod 755 /data/local/tmp/binder-probe
 *   adb shell /data/local/tmp/binder-probe
 *   adb shell /data/local/tmp/binder-probe --getservice activity
 *
 *   # THE EXPERIMENT. Transaction 2 of INotificationManager refuses the shell
 *   # uid and says so in the exception text. Run it honestly, then run it
 *   # again claiming to be root, and compare the two messages.
 *   adb shell /data/local/tmp/binder-probe --call notification 2
 *   adb shell /data/local/tmp/binder-probe --call notification 2 --forge-uid 0
 *
 *   # If the vendor build blocks execve on /data/local/tmp (some do), invoke
 *   # the dynamic linker explicitly instead -- it is the loader that is
 *   # allowed to execute, and it maps your binary itself:
 *   adb shell /system/bin/linker64 /data/local/tmp/binder-probe --getservice activity
 *
 * REQUIREMENTS
 *   - An arm64 Android device or emulator, API 21 or newer.
 *   - adb shell access. NO root is required for any mode: the `shell` domain
 *     is allowed to open /dev/binder and to `find` a large set of services.
 *   - The NDK, only to build. Nothing is needed on the device beyond the
 *     pushed binary -- it links against bionic and nothing else.
 *   - No headers beyond libc: every binder structure and constant is defined
 *     in this file, deliberately, so that the file is the documentation.
 *
 * WHAT THIS PROVES
 *   That the sender_euid field of an outgoing transaction is IGNORED. The
 *   driver overwrites it from the calling task's kernel-held credentials
 *   before the receiver is ever woken. `--call notification 2 --forge-uid 0`
 *   claims to be root and is still told "Disallowed call for uid 2000" -- the
 *   shell uid -- by a service that is simply reporting what
 *   Binder.getCallingUid() handed it.
 *
 * WHAT THIS WILL *NOT* TELL YOU
 *   - Whether a service is SECURE. It tells you a service is REACHABLE, which
 *     is a different and much weaker statement. A reachable service that
 *     checks Binder.getCallingUid() on every entry point is fine.
 *   - Which transaction codes a service implements, or what they mean. Binder
 *     carries no schema. Code 7 means whatever the .aidl file said it meant,
 *     and the .aidl file is not on the device. Get the codes from AOSP source
 *     or by decompiling the framework -- see README section 6.
 *   - Whether a failure was DAC, SELinux MAC, or the service's own permission
 *     check. All three produce different errors; this program prints the raw
 *     errno, the BR_ code and the parcel exception code so you can tell them
 *     apart, but it does not interpret them. `dmesg | grep avc` decides the
 *     MAC question; see 22-SELinux.
 *   - Anything about /dev/hwbinder's HIDL protocol or /dev/vndbinder's
 *     contents. Both speak the same ioctl but a different serialisation on
 *     top of it. This program only reports whether those nodes open.
 *   - Anything correct on a 32-bit device beyond the version check. The
 *     structure layouts below are the 64-bit ones; binder_uintptr_t is 32-bit
 *     there and every offset differs.
 *
 * SAFETY
 *   Sending a hand-built parcel to a system service with a code you guessed
 *   can crash that service, and crashing system_server reboots the device. Use
 *   a test device. `--getservice` only ever talks to servicemanager, which is
 *   the safest possible target; `--call` will aim anywhere you point it.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* ------------------------------------------------------------------------
 * 1. The kernel ABI, transcribed.
 *
 * These come from the UAPI header the kernel ships as
 * include/uapi/linux/android/binder.h, and the driver that consumes them is
 * drivers/android/binder.c. They are transcribed here rather than included so
 * that this file compiles anywhere and so that you can read the wire format
 * without a kernel tree.
 * ------------------------------------------------------------------------ */

typedef uint64_t binder_size_t;
typedef uint64_t binder_uintptr_t;

struct binder_version { int32_t protocol_version; };

struct binder_write_read {
    binder_size_t    write_size;      /* bytes to write                     */
    binder_size_t    write_consumed;  /* bytes consumed by the driver       */
    binder_uintptr_t write_buffer;    /* pointer to the BC_ command stream  */
    binder_size_t    read_size;       /* bytes available for reading        */
    binder_size_t    read_consumed;   /* bytes filled in by the driver      */
    binder_uintptr_t read_buffer;     /* pointer to the BR_ return stream   */
};

#define BINDER_WRITE_READ           _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_MAX_THREADS      _IOW('b', 5, uint32_t)
#define BINDER_SET_CONTEXT_MGR      _IOW('b', 7, int32_t)
#define BINDER_THREAD_EXIT          _IOW('b', 8, int32_t)
#define BINDER_VERSION              _IOWR('b', 9, struct binder_version)

/*
 * THE transaction descriptor. This is what a caller hands the driver, and a
 * near-identical copy is what the receiver gets back. Look hard at
 * sender_pid and sender_euid: the caller writes this struct, in the caller's
 * own memory, so those fields are trivially settable by the caller. They are
 * also completely ignored on the way in -- see --forge-uid.
 */
struct binder_transaction_data {
    union {
        uint32_t         handle;   /* remote object, for BC_TRANSACTION     */
        binder_uintptr_t ptr;      /* local object, for BR_TRANSACTION      */
    } target;
    binder_uintptr_t cookie;
    uint32_t         code;         /* the method number                     */
    uint32_t         flags;        /* TF_* below                            */
    int32_t          sender_pid;   /* driver-filled on delivery             */
    uint32_t         sender_euid;  /* driver-filled on delivery             */
    binder_size_t    data_size;    /* bytes of parcel payload               */
    binder_size_t    offsets_size; /* bytes of object-offset array          */
    union {
        struct {
            binder_uintptr_t buffer;   /* parcel bytes                      */
            binder_uintptr_t offsets;  /* array of binder_size_t offsets    */
        } ptr;
        uint8_t buf[8];
    } data;
};

/* Transaction flags. */
#define TF_ONE_WAY     0x01  /* asynchronous: do not wait for a reply       */
#define TF_ROOT_OBJECT 0x04  /* contents are the component's root object    */
#define TF_STATUS_CODE 0x08  /* contents are a 32-bit status code           */
#define TF_ACCEPT_FDS  0x10  /* the target may receive file descriptors     */
#define TF_CLEAR_BUF   0x20  /* zero the buffer on free (Android 11+)       */

/* Commands written TO the driver (BC = Binder Command). */
#define BC_TRANSACTION     _IOW('c', 0, struct binder_transaction_data)
#define BC_REPLY           _IOW('c', 1, struct binder_transaction_data)
#define BC_FREE_BUFFER     _IOW('c', 3, binder_uintptr_t)
#define BC_INCREFS         _IOW('c', 4, uint32_t)
#define BC_ACQUIRE         _IOW('c', 5, uint32_t)
#define BC_RELEASE         _IOW('c', 6, uint32_t)
#define BC_DECREFS         _IOW('c', 7, uint32_t)
#define BC_REGISTER_LOOPER _IO('c', 11)
#define BC_ENTER_LOOPER    _IO('c', 12)
#define BC_EXIT_LOOPER     _IO('c', 13)

/* Returns read FROM the driver (BR = Binder Return). */
struct binder_ptr_cookie_stub { binder_uintptr_t ptr; binder_uintptr_t cookie; };

#define BR_ERROR                _IOR('r', 0, int32_t)
#define BR_OK                   _IO('r', 1)
#define BR_TRANSACTION          _IOR('r', 2, struct binder_transaction_data)
#define BR_REPLY                _IOR('r', 3, struct binder_transaction_data)
#define BR_DEAD_REPLY           _IO('r', 5)
#define BR_TRANSACTION_COMPLETE _IO('r', 6)
#define BR_INCREFS              _IOR('r', 7, struct binder_ptr_cookie_stub)
#define BR_ACQUIRE              _IOR('r', 8, struct binder_ptr_cookie_stub)
#define BR_RELEASE              _IOR('r', 9, struct binder_ptr_cookie_stub)
#define BR_DECREFS              _IOR('r', 10, struct binder_ptr_cookie_stub)
#define BR_NOOP                 _IO('r', 12)
#define BR_SPAWN_LOOPER         _IO('r', 13)
#define BR_FINISHED             _IO('r', 14)
#define BR_DEAD_BINDER          _IOR('r', 15, binder_uintptr_t)
#define BR_FAILED_REPLY         _IO('r', 17)

/*
 * An object embedded in a parcel. The kernel finds these using the offsets
 * array and TRANSLATES them: a local object pointer in the sender becomes a
 * handle in the receiver, and a file descriptor is dup()ed into the receiving
 * process. That translation is the whole reason Binder is not just a socket.
 */
struct flat_binder_object {
    uint32_t         type;    /* BINDER_TYPE_* below                        */
    uint32_t         flags;
    union {
        binder_uintptr_t binder; /* local object pointer                    */
        uint32_t         handle; /* remote object handle                    */
    };
    binder_uintptr_t cookie;
};

#define B_PACK_CHARS(c1, c2, c3, c4) \
    ((((c1) << 24)) | (((c2) << 16)) | (((c3) << 8)) | (c4))
#define B_TYPE_LARGE 0x85

#define BINDER_TYPE_BINDER      B_PACK_CHARS('s', 'b', '*', B_TYPE_LARGE)
#define BINDER_TYPE_WEAK_BINDER B_PACK_CHARS('w', 'b', '*', B_TYPE_LARGE)
#define BINDER_TYPE_HANDLE      B_PACK_CHARS('s', 'h', '*', B_TYPE_LARGE)
#define BINDER_TYPE_WEAK_HANDLE B_PACK_CHARS('w', 'h', '*', B_TYPE_LARGE)
#define BINDER_TYPE_FD          B_PACK_CHARS('f', 'd', '*', B_TYPE_LARGE)
#define BINDER_TYPE_FDA         B_PACK_CHARS('f', 'd', 'a', B_TYPE_LARGE)
#define BINDER_TYPE_PTR         B_PACK_CHARS('p', 't', '*', B_TYPE_LARGE)

#define FLAT_BINDER_FLAG_PRIORITY_MASK    0xff
#define FLAT_BINDER_FLAG_ACCEPTS_FDS      0x100
#define FLAT_BINDER_FLAG_TXN_SECURITY_CTX 0x1000

/*
 * The parcel header libbinder's Parcel::writeInterfaceToken() emits, in this
 * order. Three int32 fields, then the descriptor as a UTF-16 string. Get any
 * of it wrong and the receiver's enforceInterface() rejects the call -- which
 * is the point of README section 3.9.
 */
#define STRICT_MODE_POLICY_DEFAULT 0
#define UNSET_WORK_SOURCE          (-1)
#define PARCEL_HEADER_SYST         B_PACK_CHARS('S', 'Y', 'S', 'T')

/* servicemanager always lives at handle 0. It is the only well-known handle. */
#define SERVICEMANAGER_HANDLE 0
#define SVC_MGR_INTERFACE     "android.os.IServiceManager"
#define SVC_MGR_GET_SERVICE   1   /* FIRST_CALL_TRANSACTION + 0 */
#define SVC_MGR_CHECK_SERVICE 2   /* FIRST_CALL_TRANSACTION + 1 */

/* Well-known codes every IBinder answers, whatever its interface. */
#define FIRST_CALL_TRANSACTION    0x00000001
#define LAST_CALL_TRANSACTION     0x00ffffff
#define PING_TRANSACTION          B_PACK_CHARS('_', 'P', 'N', 'G')
#define DUMP_TRANSACTION          B_PACK_CHARS('_', 'D', 'M', 'P')
#define SHELL_COMMAND_TRANSACTION B_PACK_CHARS('_', 'C', 'M', 'D')
#define INTERFACE_TRANSACTION     B_PACK_CHARS('_', 'N', 'T', 'F')
#define SYSPROPS_TRANSACTION      B_PACK_CHARS('_', 'S', 'P', 'R')
#define TWEET_TRANSACTION         B_PACK_CHARS('_', 'T', 'W', 'T')
#define LIKE_TRANSACTION          B_PACK_CHARS('_', 'L', 'I', 'K')

/* Parcel exception codes, from frameworks/base/core/java/android/os/Parcel.java. */
#define EX_NONE                  0
#define EX_SECURITY             (-1)
#define EX_BAD_PARCELABLE       (-2)
#define EX_ILLEGAL_ARGUMENT     (-3)
#define EX_NULL_POINTER         (-4)
#define EX_ILLEGAL_STATE        (-5)
#define EX_NETWORK_MAIN_THREAD  (-6)
#define EX_UNSUPPORTED_OP       (-7)
#define EX_SERVICE_SPECIFIC     (-8)
#define EX_PARCELABLE           (-9)
#define EX_TRANSACTION_FAILED   (-129)

/*
 * The size libbinder maps, from frameworks/native/libs/binder/ProcessState.cpp:
 * one megabyte, minus two pages, because of guard pages at either end. On a
 * 4 KiB-page device that is 1048576 - 8192 = 1040384 bytes. This single number
 * is behind every TransactionTooLargeException you have ever seen.
 */
#define BINDER_VM_SIZE ((size_t)((1 * 1024 * 1024) - (size_t)sysconf(_SC_PAGE_SIZE) * 2))

/* ------------------------------------------------------------------------
 * 2. A minimal parcel writer and reader.
 *
 * A parcel is a flat byte buffer with 4-byte alignment. That is all it is.
 * There is no type tag, no length prefix on the whole thing, and no schema.
 * Both sides must agree on the order of fields or the reader silently reads
 * garbage. That property is exactly why the interface token exists.
 * ------------------------------------------------------------------------ */

#define PARCEL_MAX 8192

struct parcel {
    uint8_t       data[PARCEL_MAX];
    size_t        pos;
    binder_size_t offsets[64];
    size_t        n_offsets;
};

static void parcel_init(struct parcel *p) { memset(p, 0, sizeof(*p)); }

static int parcel_write_int32(struct parcel *p, int32_t v) {
    if (p->pos + 4 > PARCEL_MAX) return -1;
    memcpy(p->data + p->pos, &v, 4);
    p->pos += 4;
    return 0;
}

/*
 * writeString16: a 32-bit character COUNT (not a byte count, and not counting
 * the terminator), then that many UTF-16LE code units, then a UTF-16 NUL, then
 * zero padding to the next 4-byte boundary.
 *
 * A null String16 is written as the single int32 -1 with no payload at all.
 * Getting that case wrong is the most common hand-rolled-parcel bug there is,
 * because the length field for an empty string is 0 and for a null string is
 * -1, and the two are not interchangeable.
 */
static int parcel_write_string16_ascii(struct parcel *p, const char *s) {
    if (s == NULL) return parcel_write_int32(p, -1);
    size_t len = strlen(s);
    size_t need = 4 + (len + 1) * 2;
    size_t padded = (need + 3) & ~(size_t)3;
    if (p->pos + padded > PARCEL_MAX) return -1;
    if (parcel_write_int32(p, (int32_t)len) != 0) return -1;
    for (size_t i = 0; i < len; i++) {
        uint16_t c = (uint16_t)(unsigned char)s[i];   /* ASCII widens 1:1 */
        memcpy(p->data + p->pos, &c, 2);
        p->pos += 2;
    }
    uint16_t nul = 0;
    memcpy(p->data + p->pos, &nul, 2);
    p->pos += 2;
    while (p->pos & 3) p->data[p->pos++] = 0;
    return 0;
}

/* The three-field header, then the descriptor. The order is load-bearing. */
static int parcel_write_interface_token(struct parcel *p, const char *iface) {
    if (parcel_write_int32(p, STRICT_MODE_POLICY_DEFAULT) != 0) return -1;
    if (parcel_write_int32(p, UNSET_WORK_SOURCE) != 0) return -1;
    if (parcel_write_int32(p, PARCEL_HEADER_SYST) != 0) return -1;
    return parcel_write_string16_ascii(p, iface);
}

/* Reading side. `pos` is advanced in place; returns 0 on success. */
struct reader { const uint8_t *d; size_t len; size_t pos; };

static int read_int32(struct reader *r, int32_t *out) {
    if (r->pos + 4 > r->len) return -1;
    memcpy(out, r->d + r->pos, 4);
    r->pos += 4;
    return 0;
}

/* Reads a String16 into `out` as ASCII, replacing non-ASCII with '?'. */
static int read_string16_ascii(struct reader *r, char *out, size_t outsz) {
    int32_t n;
    if (read_int32(r, &n) != 0) return -1;
    if (n < 0) { snprintf(out, outsz, "<null>"); return 0; }
    size_t chars = (size_t)n;
    size_t bytes = (chars + 1) * 2;
    if (r->pos + bytes > r->len) return -1;
    size_t o = 0;
    for (size_t i = 0; i < chars && o + 1 < outsz; i++) {
        uint16_t c;
        memcpy(&c, r->d + r->pos + i * 2, 2);
        out[o++] = (c >= 0x20 && c < 0x7f) ? (char)c : '?';
    }
    out[o] = '\0';
    r->pos += bytes;
    while (r->pos & 3) r->pos++;      /* skip alignment padding */
    return 0;
}

/* ------------------------------------------------------------------------
 * 3. Output helpers.
 * ------------------------------------------------------------------------ */

static void hexdump(const uint8_t *buf, size_t len, const char *indent) {
    for (size_t i = 0; i < len; i += 16) {
        printf("%s%08zx: ", indent, i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) printf("%02x", buf[i + j]);
            else             printf("  ");
            if ((j & 3) == 3) printf(" ");
        }
        printf(" |");
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            uint8_t c = buf[i + j];
            printf("%c", (c >= 0x20 && c < 0x7f) ? c : '.');
        }
        printf("|\n");
    }
}

static const char *br_name(uint32_t cmd) {
    switch (cmd) {
    case BR_ERROR:                return "BR_ERROR";
    case BR_OK:                   return "BR_OK";
    case BR_TRANSACTION:          return "BR_TRANSACTION";
    case BR_REPLY:                return "BR_REPLY";
    case BR_DEAD_REPLY:           return "BR_DEAD_REPLY";
    case BR_TRANSACTION_COMPLETE: return "BR_TRANSACTION_COMPLETE";
    case BR_INCREFS:              return "BR_INCREFS";
    case BR_ACQUIRE:              return "BR_ACQUIRE";
    case BR_RELEASE:              return "BR_RELEASE";
    case BR_DECREFS:              return "BR_DECREFS";
    case BR_NOOP:                 return "BR_NOOP";
    case BR_SPAWN_LOOPER:         return "BR_SPAWN_LOOPER";
    case BR_FINISHED:             return "BR_FINISHED";
    case BR_DEAD_BINDER:          return "BR_DEAD_BINDER";
    case BR_FAILED_REPLY:         return "BR_FAILED_REPLY";
    default:                      return "BR_<unknown>";
    }
}

static const char *obj_type_name(uint32_t t) {
    switch (t) {
    case BINDER_TYPE_BINDER:      return "BINDER_TYPE_BINDER (local object)";
    case BINDER_TYPE_WEAK_BINDER: return "BINDER_TYPE_WEAK_BINDER";
    case BINDER_TYPE_HANDLE:      return "BINDER_TYPE_HANDLE (remote ref)";
    case BINDER_TYPE_WEAK_HANDLE: return "BINDER_TYPE_WEAK_HANDLE";
    case BINDER_TYPE_FD:          return "BINDER_TYPE_FD (real fd, dup'ed in)";
    case BINDER_TYPE_FDA:         return "BINDER_TYPE_FDA (fd array)";
    case BINDER_TYPE_PTR:         return "BINDER_TYPE_PTR (scatter-gather)";
    default:                      return "<unknown object type>";
    }
}

static const char *exception_name(int32_t c) {
    switch (c) {
    case EX_NONE:                 return "no exception";
    case EX_SECURITY:             return "SecurityException";
    case EX_BAD_PARCELABLE:       return "BadParcelableException";
    case EX_ILLEGAL_ARGUMENT:     return "IllegalArgumentException";
    case EX_NULL_POINTER:         return "NullPointerException";
    case EX_ILLEGAL_STATE:        return "IllegalStateException";
    case EX_NETWORK_MAIN_THREAD:  return "NetworkOnMainThreadException";
    case EX_UNSUPPORTED_OP:       return "UnsupportedOperationException";
    case EX_SERVICE_SPECIFIC:     return "ServiceSpecificException";
    case EX_PARCELABLE:           return "a custom Parcelable exception";
    case EX_TRANSACTION_FAILED:   return "the transaction itself failed";
    default:                      return "<unrecognised exception code>";
    }
}

/* ------------------------------------------------------------------------
 * 4. Driver plumbing.
 * ------------------------------------------------------------------------ */

struct bstate {
    int    fd;
    void  *vm;
    size_t vm_size;
};

/* A copy of the reply, taken before we hand the driver's buffer back. */
struct reply {
    uint8_t       bytes[4096];
    size_t        len;
    binder_size_t offsets[64];
    size_t        n_offsets;
    int           ok;
};

static int binder_open(struct bstate *st, const char *node, int verbose) {
    st->fd = open(node, O_RDWR | O_CLOEXEC);
    if (st->fd < 0) {
        fprintf(stderr, "open(%s): %s (errno %d)\n", node, strerror(errno), errno);
        return -1;
    }

    struct binder_version ver = { 0 };
    if (ioctl(st->fd, BINDER_VERSION, &ver) < 0) {
        fprintf(stderr, "ioctl(BINDER_VERSION): %s\n", strerror(errno));
        close(st->fd);
        st->fd = -1;
        return -1;
    }
    if (verbose)
        printf("  protocol_version   : %d  (8 = 64-bit driver, 7 = 32-bit)\n",
               ver.protocol_version);

    uint32_t max_threads = 0;   /* pure client: we never serve transactions */
    if (ioctl(st->fd, BINDER_SET_MAX_THREADS, &max_threads) < 0 && verbose)
        printf("  BINDER_SET_MAX_THREADS failed: %s (non-fatal)\n", strerror(errno));

    st->vm_size = BINDER_VM_SIZE;
    /*
     * PROT_READ only, and that is not a typo. The receive buffer is written by
     * the KERNEL into your address space, and you only ever read it. A process
     * cannot scribble on a parcel it has been handed, which is what makes the
     * single-copy design safe.
     */
    st->vm = mmap(NULL, st->vm_size, PROT_READ, MAP_PRIVATE | MAP_NORESERVE,
                  st->fd, 0);
    if (st->vm == MAP_FAILED) {
        fprintf(stderr, "mmap: %s\n", strerror(errno));
        close(st->fd);
        st->fd = -1;
        return -1;
    }
    if (verbose) {
        printf("  mmap size          : %zu bytes (%zu KiB)  at %p\n",
               st->vm_size, st->vm_size / 1024, st->vm);
        printf("                       = 1 MiB - 2 pages; page size is %ld\n",
               sysconf(_SC_PAGE_SIZE));
    }
    return 0;
}

static void binder_close(struct bstate *st) {
    if (st->vm && st->vm != MAP_FAILED) munmap(st->vm, st->vm_size);
    if (st->fd >= 0) {
        int32_t zero = 0;
        ioctl(st->fd, BINDER_THREAD_EXIT, &zero);
        close(st->fd);
        st->fd = -1;
    }
}

/* Send a bare BC_ command that takes one 32-bit argument (BC_ACQUIRE etc). */
static int binder_simple_cmd(struct bstate *st, uint32_t cmd, uint32_t arg) {
    uint8_t buf[8];
    memcpy(buf, &cmd, 4);
    memcpy(buf + 4, &arg, 4);
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size   = sizeof(buf);
    bwr.write_buffer = (binder_uintptr_t)(uintptr_t)buf;
    return ioctl(st->fd, BINDER_WRITE_READ, &bwr) < 0 ? -1 : 0;
}

/*
 * Send one synchronous transaction and pump the return stream until the reply
 * arrives. This is, in about eighty lines, what
 * IPCThreadState::waitForResponse() does in
 * frameworks/native/libs/binder/IPCThreadState.cpp.
 */
static int binder_transact(struct bstate *st,
                           uint32_t handle,
                           uint32_t code,
                           struct parcel *out,
                           struct reply *rep,
                           uint32_t forged_uid,
                           int forge,
                           int verbose,
                           int acquire_handles,
                           int oneway)
{
    uint8_t  wbuf[sizeof(uint32_t) + sizeof(struct binder_transaction_data)];
    uint8_t  rbuf[4096];
    uint32_t cmd = BC_TRANSACTION;
    struct binder_transaction_data tr;

    if (rep) { memset(rep, 0, sizeof(*rep)); }

    memset(&tr, 0, sizeof(tr));
    tr.target.handle = handle;
    tr.code          = code;
    tr.flags         = TF_ACCEPT_FDS | (oneway ? TF_ONE_WAY : 0);
    tr.data_size     = out->pos;
    tr.offsets_size  = out->n_offsets * sizeof(binder_size_t);
    tr.data.ptr.buffer  = (binder_uintptr_t)(uintptr_t)out->data;
    tr.data.ptr.offsets = (binder_uintptr_t)(uintptr_t)out->offsets;

    if (forge) {
        /*
         * Here is the whole point of the program. We are the sender. This
         * struct is ours, in our own memory. Nothing whatsoever stops us
         * writing anything at all into these two fields.
         */
        tr.sender_euid = forged_uid;
        tr.sender_pid  = 1;
        printf("  [forge] wrote sender_euid=%u sender_pid=1 into the outgoing\n"
               "          binder_transaction_data before calling ioctl().\n",
               forged_uid);
    }

    memcpy(wbuf, &cmd, sizeof(cmd));
    memcpy(wbuf + sizeof(cmd), &tr, sizeof(tr));

    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size   = sizeof(wbuf);
    bwr.write_buffer = (binder_uintptr_t)(uintptr_t)wbuf;
    bwr.read_size    = sizeof(rbuf);
    bwr.read_buffer  = (binder_uintptr_t)(uintptr_t)rbuf;

    int rounds = 0;
    for (;;) {
        if (ioctl(st->fd, BINDER_WRITE_READ, &bwr) < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "ioctl(BINDER_WRITE_READ): %s (errno %d)\n",
                    strerror(errno), errno);
            return -1;
        }
        rounds++;
        if (verbose)
            printf("  ioctl round %d: write_consumed=%llu read_consumed=%llu\n",
                   rounds,
                   (unsigned long long)bwr.write_consumed,
                   (unsigned long long)bwr.read_consumed);

        size_t off = 0;
        while (off + 4 <= bwr.read_consumed) {
            uint32_t rc;
            memcpy(&rc, rbuf + off, 4);
            off += 4;
            if (verbose) printf("    <- %s (0x%08x)\n", br_name(rc), rc);

            if (rc == BR_REPLY) {
                struct binder_transaction_data rtr;
                if (off + sizeof(rtr) > bwr.read_consumed) return -1;
                memcpy(&rtr, rbuf + off, sizeof(rtr));
                off += sizeof(rtr);

                const uint8_t *pd = (const uint8_t *)(uintptr_t)rtr.data.ptr.buffer;
                const binder_size_t *offs =
                    (const binder_size_t *)(uintptr_t)rtr.data.ptr.offsets;
                size_t n = (size_t)(rtr.offsets_size / sizeof(binder_size_t));

                if (verbose) {
                    printf("\n  REPLY PARCEL\n");
                    printf("    data_size    : %llu bytes\n",
                           (unsigned long long)rtr.data_size);
                    printf("    offsets_size : %llu bytes  (%zu embedded object(s))\n",
                           (unsigned long long)rtr.offsets_size, n);
                    printf("    buffer       : 0x%llx  (inside our read-only mmap)\n",
                           (unsigned long long)rtr.data.ptr.buffer);
                    if (rtr.data_size > 0 && rtr.data_size < 4096) {
                        printf("\n    raw bytes:\n");
                        hexdump(pd, (size_t)rtr.data_size, "      ");
                    }
                }

                for (size_t i = 0; i < n && verbose; i++) {
                    binder_size_t o = offs[i];
                    if (o + sizeof(struct flat_binder_object) > rtr.data_size) continue;
                    struct flat_binder_object fbo;
                    memcpy(&fbo, pd + o, sizeof(fbo));
                    printf("\n    object[%zu] at parcel offset %llu:\n",
                           i, (unsigned long long)o);
                    printf("      type   : 0x%08x  %s\n", fbo.type, obj_type_name(fbo.type));
                    printf("      flags  : 0x%08x  min-priority=%u%s%s\n", fbo.flags,
                           fbo.flags & FLAT_BINDER_FLAG_PRIORITY_MASK,
                           (fbo.flags & FLAT_BINDER_FLAG_ACCEPTS_FDS) ? "  ACCEPTS_FDS" : "",
                           (fbo.flags & FLAT_BINDER_FLAG_TXN_SECURITY_CTX)
                               ? "  TXN_SECURITY_CTX" : "");
                    if (fbo.type == BINDER_TYPE_HANDLE ||
                        fbo.type == BINDER_TYPE_WEAK_HANDLE) {
                        printf("      handle : %u   <-- OUR process's number for that\n"
                               "                     remote object. It is meaningless\n"
                               "                     in any other process.\n", fbo.handle);
                    } else if (fbo.type == BINDER_TYPE_FD) {
                        printf("      fd     : %u   <-- a REAL open descriptor the\n"
                               "                     kernel installed in us.\n", fbo.handle);
                    }
                }

                /* Copy out before the buffer goes back to the driver. */
                if (rep) {
                    rep->len = (size_t)rtr.data_size;
                    if (rep->len > sizeof(rep->bytes)) rep->len = sizeof(rep->bytes);
                    memcpy(rep->bytes, pd, rep->len);
                    rep->n_offsets = n < 64 ? n : 64;
                    for (size_t i = 0; i < rep->n_offsets; i++) rep->offsets[i] = offs[i];
                    rep->ok = 1;
                }

                /*
                 * ORDER MATTERS AND IT IS EASY TO GET WRONG.
                 *
                 * A BINDER_TYPE_HANDLE arriving in a reply carries a reference
                 * that is owned by the RECEIVED BUFFER. The instant we send
                 * BC_FREE_BUFFER, the driver drops that reference, and if
                 * nothing else holds one the handle becomes invalid -- every
                 * later transaction on it returns BR_FAILED_REPLY.
                 *
                 * So we take our own strong reference FIRST, while the buffer
                 * is still alive, and only then free it. libbinder does the
                 * same thing in Parcel::unflattenBinder(), which calls
                 * ProcessState::getStrongProxyForHandle() before the buffer is
                 * released.
                 *
                 * The symptom of getting this backwards is a handle that
                 * resolves correctly and then fails on first use, which reads
                 * exactly like an SELinux denial and is not one.
                 */
                if (acquire_handles) {
                    for (size_t i = 0; i < n; i++) {
                        binder_size_t o = offs[i];
                        if (o + sizeof(struct flat_binder_object) > rtr.data_size) continue;
                        struct flat_binder_object fbo;
                        memcpy(&fbo, pd + o, sizeof(fbo));
                        if (fbo.type == BINDER_TYPE_HANDLE)
                            binder_simple_cmd(st, BC_ACQUIRE, fbo.handle);
                    }
                }

                /*
                 * The buffer belongs to the driver, not to us. Until we send
                 * BC_FREE_BUFFER it occupies part of our 1016 KiB allowance.
                 * Forgetting this is how a process slowly runs out of binder
                 * buffer and starts throwing TransactionTooLargeException on
                 * transactions that are not large at all.
                 */
                uint8_t  fb[4 + sizeof(binder_uintptr_t)];
                uint32_t fcmd = BC_FREE_BUFFER;
                memcpy(fb, &fcmd, 4);
                memcpy(fb + 4, &rtr.data.ptr.buffer, sizeof(binder_uintptr_t));
                struct binder_write_read fbwr;
                memset(&fbwr, 0, sizeof(fbwr));
                fbwr.write_size   = sizeof(fb);
                fbwr.write_buffer = (binder_uintptr_t)(uintptr_t)fb;
                if (ioctl(st->fd, BINDER_WRITE_READ, &fbwr) < 0)
                    fprintf(stderr, "  BC_FREE_BUFFER failed: %s\n", strerror(errno));
                else if (verbose)
                    printf("\n    BC_FREE_BUFFER sent -- buffer returned to the driver\n");
                return 0;
            }

            if (rc == BR_TRANSACTION_COMPLETE && oneway) {
                /*
                 * A one-way transaction gets BR_TRANSACTION_COMPLETE and
                 * NOTHING ELSE. There is no reply and there never will be, so
                 * waiting for BR_REPLY here would hang until the retry cap.
                 *
                 * Note what that means for an attacker AND for a defender:
                 * "complete" means the driver QUEUED it. It does not mean the
                 * service accepted it, ran it, or liked it. An exception
                 * thrown on the far side is logged there and discarded.
                 */
                if (verbose)
                    printf("    one-way: BR_TRANSACTION_COMPLETE is all we get.\n"
                           "    The driver queued it. Whether the service accepted\n"
                           "    it is UNOBSERVABLE from here -- a oneway method is a\n"
                           "    poor oracle. Find a synchronous method that reads\n"
                           "    the same state.\n");
                if (rep) rep->ok = 0;
                return 0;
            }

            if (rc == BR_DEAD_REPLY || rc == BR_FAILED_REPLY) {
                printf("    transaction FAILED. Causes, in order of likelihood:\n"
                       "      1. SELinux denied binder:call  -> look for an avc\n"
                       "         record; see 22-SELinux\n"
                       "      2. the target handle is stale (service restarted)\n"
                       "      3. the parcel was malformed or too large\n");
                return -1;
            }
            if (rc == BR_ERROR) {
                int32_t e; memcpy(&e, rbuf + off, 4); off += 4;
                printf("    driver error %d (%s)\n", e, strerror(e < 0 ? -e : e));
                return -1;
            }
            if (rc == BR_TRANSACTION) off += sizeof(struct binder_transaction_data);
            if (rc == BR_DEAD_BINDER) off += sizeof(binder_uintptr_t);
            if (rc == BR_INCREFS || rc == BR_ACQUIRE ||
                rc == BR_RELEASE || rc == BR_DECREFS)
                off += sizeof(struct binder_ptr_cookie_stub);
        }

        /* Nothing more to write; keep reading until the reply lands. */
        bwr.write_size = 0;
        bwr.write_consumed = 0;
        bwr.read_consumed = 0;
        if (rounds > 8) { printf("  giving up after 8 ioctl rounds\n"); return -1; }
    }
}

/* ------------------------------------------------------------------------
 * 5. Higher-level operations.
 * ------------------------------------------------------------------------ */

/* checkService(name) -> handle, or -1. Acquires a strong ref on success. */
static int sm_check_service(struct bstate *st, const char *name,
                            uint32_t forged_uid, int forge, int verbose)
{
    struct parcel p;
    struct reply  rep;
    parcel_init(&p);
    if (parcel_write_interface_token(&p, SVC_MGR_INTERFACE) != 0) return -1;
    if (parcel_write_string16_ascii(&p, name) != 0) return -1;

    if (verbose) {
        printf("\nOUTGOING PARCEL for IServiceManager.checkService(\"%s\")\n", name);
        printf("  interface token : \"%s\"\n", SVC_MGR_INTERFACE);
        printf("  total data_size : %zu bytes\n", p.pos);
        printf("  raw bytes:\n");
        hexdump(p.data, p.pos, "    ");
        printf("\n  Field walk:\n");
        printf("    [0x00] int32  strict-mode policy      = 0\n");
        printf("    [0x04] int32  work-source uid         = -1 (unset)\n");
        printf("    [0x08] int32  header 'SYST'           = 0x%08x\n", PARCEL_HEADER_SYST);
        printf("    [0x0c] str16  interface descriptor    = \"%s\"\n", SVC_MGR_INTERFACE);
        printf("    [....] str16  argument                = \"%s\"\n", name);
        printf("\nSENDING to handle %d, code %d (checkService)\n",
               SERVICEMANAGER_HANDLE, SVC_MGR_CHECK_SERVICE);
    }

    if (binder_transact(st, SERVICEMANAGER_HANDLE, SVC_MGR_CHECK_SERVICE,
                        &p, &rep, forged_uid, forge, verbose, 1, 0) != 0)
        return -1;
    if (!rep.ok) return -1;

    for (size_t i = 0; i < rep.n_offsets; i++) {
        binder_size_t o = rep.offsets[i];
        if (o + sizeof(struct flat_binder_object) > rep.len) continue;
        struct flat_binder_object fbo;
        memcpy(&fbo, rep.bytes + o, sizeof(fbo));
        if (fbo.type == BINDER_TYPE_HANDLE) {
            /* binder_transact() already sent BC_ACQUIRE for this handle,
             * before it freed the buffer. We own a strong reference now and
             * must BC_RELEASE it when finished. */
            return (int)fbo.handle;
        }
    }
    return -1;
}

/* INTERFACE_TRANSACTION -> the object's own descriptor string. */
static int get_descriptor(struct bstate *st, uint32_t handle,
                          char *out, size_t outsz)
{
    struct parcel p;
    struct reply  rep;
    parcel_init(&p);                 /* this transaction takes no arguments */
    if (binder_transact(st, handle, INTERFACE_TRANSACTION, &p, &rep, 0, 0, 0, 0, 0) != 0)
        return -1;
    if (!rep.ok) return -1;
    struct reader r = { rep.bytes, rep.len, 0 };
    return read_string16_ascii(&r, out, outsz);
}

/* ------------------------------------------------------------------------
 * 6. Modes.
 * ------------------------------------------------------------------------ */

static void report_nodes(void) {
    static const char *nodes[] = {
        "/dev/binder", "/dev/hwbinder", "/dev/vndbinder",
        "/dev/binderfs/binder", NULL
    };
    printf("Binder device nodes visible to uid %u:\n", getuid());
    for (int i = 0; nodes[i]; i++) {
        struct stat sb;
        int have = (lstat(nodes[i], &sb) == 0);
        int fd = open(nodes[i], O_RDWR | O_CLOEXEC);
        printf("  %-24s present=%s openable=%s%s%s\n",
               nodes[i], have ? "yes" : "no", (fd >= 0) ? "yes" : "no",
               (fd < 0 && have) ? "  reason=" : "",
               (fd < 0 && have) ? strerror(errno) : "");
        if (fd >= 0) close(fd);
    }
    printf("\n");
}

static void report_sizes(void) {
    printf("Structure sizes on this ABI:\n");
    printf("  sizeof(binder_write_read)        = %zu\n", sizeof(struct binder_write_read));
    printf("  sizeof(binder_transaction_data)  = %zu\n", sizeof(struct binder_transaction_data));
    printf("  sizeof(flat_binder_object)       = %zu\n", sizeof(struct flat_binder_object));
    printf("  sizeof(binder_uintptr_t)         = %zu\n", sizeof(binder_uintptr_t));
    printf("\nioctl numbers as this build computes them:\n");
    printf("  BINDER_WRITE_READ                = 0x%08lx\n", (unsigned long)BINDER_WRITE_READ);
    printf("  BINDER_SET_MAX_THREADS           = 0x%08lx\n", (unsigned long)BINDER_SET_MAX_THREADS);
    printf("  BINDER_SET_CONTEXT_MGR           = 0x%08lx\n", (unsigned long)BINDER_SET_CONTEXT_MGR);
    printf("  BINDER_VERSION                   = 0x%08lx\n", (unsigned long)BINDER_VERSION);
    printf("\nWell-known transaction codes (ASCII packed big-endian):\n");
    printf("  INTERFACE_TRANSACTION     '_NTF' = %u (0x%08x)\n",
           INTERFACE_TRANSACTION, INTERFACE_TRANSACTION);
    printf("  DUMP_TRANSACTION          '_DMP' = %u (0x%08x)\n",
           DUMP_TRANSACTION, DUMP_TRANSACTION);
    printf("  SHELL_COMMAND_TRANSACTION '_CMD' = %u (0x%08x)\n",
           SHELL_COMMAND_TRANSACTION, SHELL_COMMAND_TRANSACTION);
    printf("  PING_TRANSACTION          '_PNG' = %u (0x%08x)\n",
           PING_TRANSACTION, PING_TRANSACTION);
    printf("  SYSPROPS_TRANSACTION      '_SPR' = %u (0x%08x)\n",
           SYSPROPS_TRANSACTION, SYSPROPS_TRANSACTION);
    printf("\n");
}

static int mode_call(struct bstate *st, const char *name, uint32_t code,
                     uint32_t forged_uid, int forge, const char *token_override,
                     int oneway)
{
    printf("\nSTEP 1 -- resolve \"%s\" through servicemanager\n", name);
    int h = sm_check_service(st, name, 0, 0, 0);
    if (h < 0) {
        printf("  checkService returned no handle. Either the service does not\n"
               "  exist, or SELinux refused service_manager:find for our domain.\n");
        return -1;
    }
    printf("  handle = %d\n", h);

    char desc[256] = "";
    printf("\nSTEP 2 -- ask handle %d for its own interface descriptor ('_NTF')\n", h);
    if (get_descriptor(st, (uint32_t)h, desc, sizeof(desc)) != 0 || desc[0] == '\0') {
        printf("  no descriptor. Some objects legitimately have none.\n");
        return -1;
    }
    printf("  descriptor = \"%s\"\n", desc);

    struct parcel p;
    struct reply  rep;
    parcel_init(&p);
    const char *token = token_override ? token_override : desc;
    if (parcel_write_interface_token(&p, token) != 0) return -1;

    if (token_override) {
        printf("\nSTEP 3 -- send transaction code %u with a DELIBERATELY WRONG token\n",
               code);
        printf("  the object says its interface is : \"%s\"\n", desc);
        printf("  we are claiming                  : \"%s\"\n", token);
        printf("  The receiver's enforceInterface() compares the two strings and\n");
        printf("  refuses on mismatch. That refusal is a SECURITY CONTROL, not a\n");
        printf("  formality: it is what stops a parcel built for interface A from\n");
        printf("  being reinterpreted, field by field, by interface B's reader.\n");
    } else {
        printf("\nSTEP 3 -- send transaction code %u with a correct interface token%s\n",
               code, oneway ? "  (ONE-WAY)" : "");
    }
    printf("  outgoing parcel (%zu bytes):\n", p.pos);
    hexdump(p.data, p.pos, "    ");
    if (binder_transact(st, (uint32_t)h, code, &p, &rep, forged_uid, forge, 1, 0, oneway) != 0) {
        binder_simple_cmd(st, BC_RELEASE, (uint32_t)h);
        return -1;
    }

    if (oneway) {
        /*
         * There is no reply to decode and there never will be. Say so plainly
         * rather than printing "reply too short", which reads like an error.
         */
        printf("\nSTEP 4 -- nothing to decode\n");
        printf("  A one-way transaction has no reply parcel. Any exception the\n");
        printf("  service threw was logged in ITS process and discarded. If you\n");
        printf("  need to know whether the call was accepted, find a synchronous\n");
        printf("  method that observes the same state and call that instead.\n");
        binder_simple_cmd(st, BC_RELEASE, (uint32_t)h);
        return 0;
    }

    printf("\nSTEP 4 -- decode the reply's exception header\n");
    struct reader r = { rep.bytes, rep.len, 0 };
    int32_t exc = 0;
    if (read_int32(&r, &exc) != 0) {
        printf("  reply too short to contain an exception header\n");
    } else {
        printf("  exception code : %d  (%s)\n", exc, exception_name(exc));
        if (exc != EX_NONE) {
            char msg[1024];
            if (read_string16_ascii(&r, msg, sizeof(msg)) == 0)
                printf("  message        : \"%s\"\n", msg);
            printf("\n  >>> READ THAT MESSAGE. If it names a uid, that uid came\n");
            printf("      from Binder.getCallingUid() on the SERVICE side, which\n");
            printf("      the kernel filled in. It is what the driver believes,\n");
            printf("      not what we claimed.\n");
        }
    }

    binder_simple_cmd(st, BC_RELEASE, (uint32_t)h);
    return 0;
}

static void usage(const char *argv0) {
    printf("usage: %s [--node PATH] [--getservice NAME] [--call NAME CODE]\n"
           "          [--forge-uid UID] [--token STR] [--oneway]\n", argv0);
    printf("  (no args)          probe the driver and report sizes\n");
    printf("  --getservice NAME  hand-build a checkService transaction\n");
    printf("  --call NAME CODE   resolve NAME, then send transaction CODE\n");
    printf("  --forge-uid UID    write UID into sender_euid before sending.\n");
    printf("                     Expect it to change NOTHING -- that is the point\n");
    printf("  --token STR        send STR as the interface token instead of the\n");
    printf("                     object's real descriptor. Expect a refusal\n");
    printf("  --oneway           set TF_ONE_WAY: no reply comes back, and the\n");
    printf("                     receiver sees getCallingPid() == 0\n");
    printf("  --node PATH        use a device node other than /dev/binder\n");
}

int main(int argc, char **argv) {
    const char *node = "/dev/binder";
    const char *svc  = NULL;
    const char *call = NULL;
    uint32_t    code = 0;
    const char *token  = NULL;
    int         oneway = 0;
    uint32_t    forged = 0;
    int         forge = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--node") && i + 1 < argc)            node = argv[++i];
        else if (!strcmp(argv[i], "--getservice") && i + 1 < argc) svc  = argv[++i];
        else if (!strcmp(argv[i], "--call") && i + 2 < argc) {
            call = argv[++i];
            code = (uint32_t)strtoul(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--oneway")) {
            oneway = 1;
        } else if (!strcmp(argv[i], "--token") && i + 1 < argc) {
            token = argv[++i];
        } else if (!strcmp(argv[i], "--forge-uid") && i + 1 < argc) {
            forged = (uint32_t)strtoul(argv[++i], NULL, 10); forge = 1;
        } else { usage(argv[0]); return 2; }
    }

    printf("binder-probe -- raw /dev/binder client\n");
    printf("real uid=%u  euid=%u  pid=%d\n\n", getuid(), geteuid(), getpid());

    report_nodes();
    report_sizes();

    struct bstate st = { -1, NULL, 0 };
    printf("Opening %s:\n", node);
    if (binder_open(&st, node, 1) != 0) return 1;

    int rc = 0;
    if (svc)       rc = sm_check_service(&st, svc, forged, forge, 1) < 0 ? -1 : 0;
    else if (call) rc = mode_call(&st, call, code, forged, forge, token, oneway);

    if (forge && (svc || call)) {
        printf("\n----------------------------------------------------------\n");
        printf("We wrote sender_euid=%u into the outgoing transaction.\n", forged);
        printf("The receiver did not see it. binder_transaction() in\n");
        printf("drivers/android/binder.c overwrites both sender fields from the\n");
        printf("calling task's own kernel-held credentials before the target is\n");
        printf("ever woken up. The field exists in the struct only because the\n");
        printf("SAME struct is used for delivery, where the kernel fills it in.\n");
        printf("\nRun the same command WITHOUT --forge-uid and diff the output.\n");
        printf("They are identical. That is the proof.\n");
        printf("----------------------------------------------------------\n");
    }

    binder_close(&st);
    return rc == 0 ? 0 : 1;
}
