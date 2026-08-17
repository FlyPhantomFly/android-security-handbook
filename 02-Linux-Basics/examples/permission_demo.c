/*
 * =============================================================================
 * permission_demo.c -- the permission rules, demonstrated from the syscall side
 * Chapter 02 -- Linux Basics
 * =============================================================================
 *
 * PURPOSE
 *   `ls -l` shows you the bits. This program shows you the DECISION. It creates
 *   a scratch directory, builds files and directories with specific modes, then
 *   calls open(), opendir() and access() on them and prints exactly what the
 *   kernel answered and which errno it set.
 *
 *   Five things become concrete that are easy to misread from documentation:
 *
 *     1. The kernel picks ONE permission class and stops. Mode 0466 makes a
 *        file unwritable by its own owner while the whole world may write it.
 *     2. On a directory, x means TRAVERSE and r means LIST. They are separate,
 *        and having only x is exactly what /data/data does on Android.
 *     3. You need x on EVERY component of a path, and the error names the leaf
 *        rather than the directory that actually stopped you.
 *     4. umask silently removes bits from every file you create.
 *     5. Deleting a file is governed by w on the DIRECTORY, not on the file --
 *        which is why the sticky bit exists.
 *
 *   Everything happens inside one directory that the program creates and then
 *   removes. It does not touch anything else, needs no privilege, and opens no
 *   network connection.
 *
 * USAGE
 *   Compile and run on Linux or WSL:
 *       gcc -Wall -Wextra -O1 -o permission_demo permission_demo.c
 *       ./permission_demo
 *
 *   Use a specific scratch directory (default: ./permdemo_scratch):
 *       ./permission_demo /tmp/mydemo
 *
 *   Cross-compile for an Android device with the NDK, then run it there:
 *       $NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang \
 *           -o permission_demo permission_demo.c
 *       adb push permission_demo /data/local/tmp/
 *       adb shell chmod 755 /data/local/tmp/permission_demo
 *       adb shell /data/local/tmp/permission_demo /data/local/tmp/permdemo
 *
 * REQUIREMENTS
 *   Any C99 compiler and a POSIX system. No libraries beyond libc. On Android,
 *   run it from /data/local/tmp -- /sdcard is mounted noexec and nosuid, so a
 *   binary there will not run at all, whatever its mode.
 *
 * WHAT THIS PROGRAM WILL NOT TELL YOU
 *   - It will not demonstrate anything useful if you run it as ROOT. UID 0
 *     bypasses the discretionary checks, so every test "passes" and teaches
 *     nothing. The program detects this and says so. Run it as an ordinary
 *     user.
 *   - It only exercises the FIRST of the five gates that an open() must pass:
 *     the classic permission bits. It cannot show you an SELinux denial (use
 *     `dmesg | grep avc` as root), a mount-flag denial (read /proc/mounts), a
 *     capability difference, or a seccomp rejection. All five produce the same
 *     "Permission denied" from the shell, and distinguishing them is the real
 *     diagnostic skill.
 *   - It says nothing about whether a mode is APPROPRIATE. 0644 on an APK is
 *     correct; 0644 on a private key is a finding. Context decides, not the
 *     number.
 *   - Results may differ inside a container, on a filesystem mounted with
 *     unusual options, or on a filesystem that does not implement UNIX
 *     permissions at all (FAT, some network mounts, and the Windows drives
 *     visible from WSL under /mnt/c).
 *
 * SEE ALSO
 *   ../labs/lab-01-filesystem-and-permissions.md
 *   ../examples/permission-arithmetic-drill.md
 *   ../scripts/explain-mode.sh
 * =============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#define PATHMAX 512

static char scratch[PATHMAX];

/* ------------------------------------------------------------------------- */
/* Output helpers                                                            */
/* ------------------------------------------------------------------------- */

static void rule(void)
{
    puts("==============================================================================");
}

static void section(const char *title)
{
    putchar('\n');
    rule();
    printf(" %s\n", title);
    rule();
}

/* Turn an errno value into the name a pentester actually recognises. */
static const char *errno_name(int e)
{
    switch (e) {
    case 0:       return "success";
    case EACCES:  return "EACCES  (permission denied by the mode bits)";
    case EPERM:   return "EPERM   (operation not permitted -- often a capability or LSM)";
    case ENOENT:  return "ENOENT  (no such file -- or a missing x on a parent directory)";
    case ENOTDIR: return "ENOTDIR (a path component is not a directory)";
    case EISDIR:  return "EISDIR  (it is a directory)";
    case ELOOP:   return "ELOOP   (too many symlinks -- a link loop)";
    case EROFS:   return "EROFS   (read-only filesystem -- a MOUNT flag, not a mode)";
    default:      return strerror(e);
    }
}

/* Print the mode of a path exactly as ls -l would render the last nine bits. */
static void show_mode(const char *label, const char *path)
{
    struct stat st;
    char s[11];
    mode_t m;

    if (lstat(path, &st) != 0) {
        printf("  %-22s <cannot stat: %s>\n", label, strerror(errno));
        return;
    }
    m = st.st_mode;

    s[0] = S_ISDIR(m)  ? 'd' :
           S_ISLNK(m)  ? 'l' :
           S_ISCHR(m)  ? 'c' :
           S_ISBLK(m)  ? 'b' :
           S_ISFIFO(m) ? 'p' :
           S_ISSOCK(m) ? 's' : '-';
    s[1] = (m & S_IRUSR) ? 'r' : '-';
    s[2] = (m & S_IWUSR) ? 'w' : '-';
    s[3] = (m & S_ISUID) ? ((m & S_IXUSR) ? 's' : 'S') : ((m & S_IXUSR) ? 'x' : '-');
    s[4] = (m & S_IRGRP) ? 'r' : '-';
    s[5] = (m & S_IWGRP) ? 'w' : '-';
    s[6] = (m & S_ISGID) ? ((m & S_IXGRP) ? 's' : 'S') : ((m & S_IXGRP) ? 'x' : '-');
    s[7] = (m & S_IROTH) ? 'r' : '-';
    s[8] = (m & S_IWOTH) ? 'w' : '-';
    s[9] = (m & S_ISVTX) ? ((m & S_IXOTH) ? 't' : 'T') : ((m & S_IXOTH) ? 'x' : '-');
    s[10] = '\0';

    printf("  %-22s %s  %04o  uid=%ld gid=%ld  %s\n",
           label, s, (unsigned)(m & 07777),
           (long)st.st_uid, (long)st.st_gid, path);
}

/* Try to open a path and report the verdict. Returns 1 on success. */
static int try_open(const char *what, const char *path, int flags)
{
    int fd = open(path, flags);
    if (fd >= 0) {
        printf("    %-42s ALLOWED\n", what);
        close(fd);
        return 1;
    }
    printf("    %-42s DENIED  %s\n", what, errno_name(errno));
    return 0;
}

static int try_opendir(const char *what, const char *path)
{
    DIR *d = opendir(path);
    if (d) {
        int n = 0;
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (strcmp(e->d_name, ".") && strcmp(e->d_name, ".."))
                n++;
        }
        printf("    %-42s ALLOWED  (%d entr%s listed)\n",
               what, n, n == 1 ? "y" : "ies");
        closedir(d);
        return 1;
    }
    printf("    %-42s DENIED  %s\n", what, errno_name(errno));
    return 0;
}

static void jp(char *out, const char *a, const char *b)
{
    snprintf(out, PATHMAX, "%s/%s", a, b);
}

/*
 * Write a short string, checking the result. glibc marks write() as
 * warn_unused_result, so ignoring it outright produces a warning under
 * -Wall -Wextra. The content itself is not load-bearing in any demo.
 */
static void wr(int fd, const char *s)
{
    size_t n = strlen(s);
    ssize_t w = write(fd, s, n);
    if (w != (ssize_t)n)
        fprintf(stderr, "  (short write, harmless here: %s)\n", strerror(errno));
}

/* ------------------------------------------------------------------------- */
/* Demonstrations                                                            */
/* ------------------------------------------------------------------------- */

/*
 * DEMO 1
 * The kernel picks ONE class and stops. It does not merge them, and it does not
 * fall through to a more permissive class when the first one denies you.
 */
static void demo_one_class_wins(void)
{
    char p[PATHMAX];
    int fd;

    section("DEMO 1 -- the kernel picks ONE permission class and stops");

    jp(p, scratch, "mode0466.txt");
    fd = open(p, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) { perror("  create"); return; }
    wr(fd, "content\n");
    close(fd);
    chmod(p, 0466);

    show_mode("we own this file", p);
    puts("");
    puts("  Mode 0466 is -r--rw-rw-.  The owner class is r--, group is rw-,");
    puts("  other is rw-.  We ARE the owner, so the owner class is chosen and");
    puts("  the kernel stops.  It never consults group or other, even though");
    puts("  both are more permissive.");
    puts("");
    try_open("open for READ  as the owner", p, O_RDONLY);
    try_open("open for WRITE as the owner", p, O_WRONLY);
    puts("");
    puts("  The owner has strictly LESS access than a stranger would. This is");
    puts("  the single most counter-intuitive rule in UNIX permissions, and it");
    puts("  is why the rule is 'one class is chosen', not 'permissions are");
    puts("  checked'.");

    chmod(p, 0600);
    unlink(p);
}

/*
 * DEMO 2
 * On a directory, x means traverse and r means list. Android's /data/data is
 * drwxrwx--x precisely so that apps can be reached by name but not enumerated.
 */
static void demo_dir_x_vs_r(void)
{
    char d[PATHMAX], f[PATHMAX];
    int fd;

    section("DEMO 2 -- on a directory, x is TRAVERSE and r is LIST");

    jp(d, scratch, "d_traverse_only");
    if (mkdir(d, 0700) != 0 && errno != EEXIST) { perror("  mkdir"); return; }
    jp(f, d, "known_name.txt");
    fd = open(f, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) { perror("  create"); return; }
    wr(fd, "reachable\n");
    close(fd);

    chmod(d, 0111);                      /* --x--x--x */
    show_mode("directory", d);
    puts("");
    puts("  Mode 0111 gives execute and NOT read. Watch what each permits:");
    puts("");
    try_opendir("opendir()  -- needs r on the directory", d);
    try_open   ("open() a name we already know -- needs x", f, O_RDONLY);
    puts("");
    puts("  This is exactly /data/data on every Android device: drwxrwx--x.");
    puts("  Any process may reach a package directory whose name it knows, and");
    puts("  no process may list the directory to discover which apps are");
    puts("  installed. The list of installed apps is itself sensitive.");
    puts("");
    puts("  The weakness follows directly: the control is only as good as the");
    puts("  secrecy of the NAMES, and names leak -- into logs, stack traces,");
    puts("  crash reports, and error messages.");

    chmod(d, 0700);
    unlink(f);
    rmdir(d);
}

/*
 * DEMO 3
 * Every component of a path needs x, and the error names the leaf rather than
 * the directory that actually blocked you.
 */
static void demo_path_traversal(void)
{
    char a[PATHMAX], b[PATHMAX], f[PATHMAX];
    int fd;

    section("DEMO 3 -- you need x on EVERY component, and the error misleads");

    jp(a, scratch, "outer");
    if (mkdir(a, 0700) != 0 && errno != EEXIST) { perror("  mkdir outer"); return; }
    jp(b, a, "inner");
    if (mkdir(b, 0755) != 0 && errno != EEXIST) { perror("  mkdir inner"); return; }
    jp(f, b, "target.txt");
    fd = open(f, O_CREAT | O_WRONLY | O_TRUNC, 0666);
    if (fd < 0) { perror("  create"); return; }
    wr(fd, "data\n");
    close(fd);

    puts("  The FILE is mode 0666 -- world readable and writable.");
    puts("  The INNER directory is 0755 -- perfectly traversable.");
    puts("  The OUTER directory is about to lose its execute bit.");
    puts("");
    show_mode("outer dir", a);
    show_mode("inner dir", b);
    show_mode("the file itself", f);

    chmod(a, 0600);                      /* rw-------  : no x at all */
    puts("");
    show_mode("outer dir, now", a);
    puts("");
    try_open("open the 0666 file through the 0600 dir", f, O_RDONLY);
    puts("");
    puts("  Denied -- and note that the error is about the FILE, while the");
    puts("  cause is a directory two levels up. Walking the path with");
    puts("  `ls -ld` on every component is the only reliable way to find the");
    puts("  component that actually stopped you:");
    printf("      ls -ld / %s %s %s\n", scratch, a, b);
    puts("");
    puts("  A 0666 file is not necessarily reachable, and a 0600 file inside a");
    puts("  world-traversable directory may be the real exposure. Review the");
    puts("  whole path, never the leaf alone.");

    chmod(a, 0700);
    unlink(f);
    rmdir(b);
    rmdir(a);
}

/*
 * DEMO 4
 * umask removes bits from everything you create, silently.
 */
static void demo_umask(void)
{
    char p[PATHMAX];
    mode_t old;
    int fd;

    section("DEMO 4 -- umask silently removes bits from what you create");

    old = umask(0);
    umask(old);
    printf("  current umask: %04o\n", (unsigned)old);
    puts("");
    puts("  The kernel applies:  actual_mode = requested_mode & ~umask");
    puts("  A umask can only ever take permission away, never add it. It is");
    puts("  inherited across fork() and execve().");
    puts("");

    umask(0022);
    jp(p, scratch, "umask022.txt");
    fd = open(p, O_CREAT | O_WRONLY | O_TRUNC, 0666);
    if (fd >= 0) close(fd);
    show_mode("requested 0666, umask 022", p);
    unlink(p);

    umask(0077);
    jp(p, scratch, "umask077.txt");
    fd = open(p, O_CREAT | O_WRONLY | O_TRUNC, 0666);
    if (fd >= 0) close(fd);
    show_mode("requested 0666, umask 077", p);
    unlink(p);

    umask(0000);
    jp(p, scratch, "umask000.txt");
    fd = open(p, O_CREAT | O_WRONLY | O_TRUNC, 0666);
    if (fd >= 0) close(fd);
    show_mode("requested 0666, umask 000", p);
    unlink(p);

    umask(old);
    puts("");
    puts("  Android's zygote sets a restrictive umask before an app's code");
    puts("  runs. That is why openFileOutput(name, MODE_PRIVATE) produces an");
    puts("  0600 file rather than an 0666 one, and why a native helper the app");
    puts("  spawns inherits the same protection -- unless the app deliberately");
    puts("  throws it away with an explicit chmod(0777), which is a finding.");
}

/*
 * DEMO 5
 * Deleting is governed by w on the DIRECTORY, not on the file. Hence sticky.
 */
static void demo_delete_needs_dir_write(void)
{
    char d[PATHMAX], f[PATHMAX];
    int fd;

    section("DEMO 5 -- deleting a file is governed by the DIRECTORY, not the file");

    jp(d, scratch, "deldemo");
    if (mkdir(d, 0700) != 0 && errno != EEXIST) { perror("  mkdir"); return; }
    jp(f, d, "readonly.txt");
    fd = open(f, O_CREAT | O_WRONLY | O_TRUNC, 0444);
    if (fd < 0) { perror("  create"); return; }
    wr(fd, "immutable?\n");
    close(fd);
    chmod(f, 0444);

    show_mode("directory (writable)", d);
    show_mode("file (read-only)", f);
    puts("");
    try_open("open the 0444 file for WRITE", f, O_WRONLY);
    if (unlink(f) == 0)
        puts("    unlink() the same 0444 file             ALLOWED");
    else
        printf("    unlink() the same 0444 file             DENIED  %s\n",
               errno_name(errno));
    puts("");
    puts("  Unwritable, and deleted anyway -- because removing a name modifies");
    puts("  the DIRECTORY, and we have w on the directory.");
    puts("");
    puts("  That is the entire reason the sticky bit exists. Without it, w on a");
    puts("  shared directory would let any user delete any other user's files.");
    puts("  With it (mode 1777, as on /tmp), only an entry's owner may delete");
    puts("  or rename it. Look for drwxrwxrwt -- the t is the sticky bit.");

    rmdir(d);
}

/* ------------------------------------------------------------------------- */
/* main                                                                      */
/* ------------------------------------------------------------------------- */

int main(int argc, char **argv)
{
    const char *base = (argc > 1) ? argv[1] : "./permdemo_scratch";
    struct stat st;

    rule();
    puts(" permission_demo -- the permission rules, from the syscall side");
    rule();

    printf("  uid=%ld euid=%ld  gid=%ld egid=%ld\n",
           (long)getuid(), (long)geteuid(), (long)getgid(), (long)getegid());

    if (geteuid() == 0) {
        puts("");
        puts("  !! You are running as ROOT (euid 0).");
        puts("  !! UID 0 bypasses the discretionary permission checks entirely,");
        puts("  !! so every test below will be ALLOWED and none of them will");
        puts("  !! teach you anything. Re-run as an ordinary user.");
        puts("");
        puts("  On Android:  adb unroot   (or just use the default shell user)");
        puts("  On Linux:    do not use sudo");
        return 2;
    }

    snprintf(scratch, sizeof(scratch), "%s", base);

    if (mkdir(scratch, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "  cannot create scratch directory %s: %s\n",
                scratch, strerror(errno));
        fprintf(stderr, "  pass a writable path as the first argument, e.g.\n");
        fprintf(stderr, "      ./permission_demo /data/local/tmp/permdemo\n");
        return 1;
    }
    if (stat(scratch, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "  %s is not a directory\n", scratch);
        return 1;
    }

    printf("  scratch directory: %s   (created, and removed at the end)\n", scratch);
    puts("  nothing outside it is read, written or modified.");

    demo_one_class_wins();
    demo_dir_x_vs_r();
    demo_path_traversal();
    demo_umask();
    demo_delete_needs_dir_write();

    section("WHAT THIS DID NOT SHOW YOU");
    puts("  Only the first of the five gates an open() must pass was exercised:");
    puts("");
    puts("    1. x on every directory in the path        <- demo 3");
    puts("    2. the mode bits of the ONE matching class <- demos 1, 2, 5");
    puts("    3. SELinux: source domain vs target type   -- dmesg | grep avc");
    puts("    4. mount flags: ro / noexec / nosuid       -- cat /proc/mounts");
    puts("    5. seccomp: is the syscall itself allowed  -- grep Seccomp /proc/self/status");
    puts("");
    puts("  All five produce 'Permission denied'. Telling them apart is the");
    puts("  diagnostic skill that this chapter exists to build.");

    if (rmdir(scratch) == 0)
        printf("\n  cleaned up: %s removed\n\n", scratch);
    else
        printf("\n  note: %s not removed (%s) -- remove it yourself\n\n",
               scratch, strerror(errno));

    return 0;
}
