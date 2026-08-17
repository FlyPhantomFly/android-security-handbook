/*
 * investigate-main.c -- CLI runner for libinvestigate.so (chapter 68 labs).
 *
 * PURPOSE
 *   Gives the fixture library a way to be *run*, so that the labs can close
 *   the hypothesis loop with an experiment rather than an argument. Static
 *   reading tells you what you think the library does; this binary tells you
 *   what it did.
 *
 * BUILD
 *   ./build.sh     -- builds this and libinvestigate.so out of tree.
 *
 * USAGE  (on the device, after `adb push`)
 *   # the vendor build on the Redmi blocks execve under /data/local/tmp, so
 *   # the push and the chmod both succeed and the run is still refused; invoke
 *   # through the dynamic linker, which LOADS the binary instead of exec'ing it:
 *   adb shell /system/bin/linker64 /data/local/tmp/ch68/investigate <key>
 *
 *   Exit status: 0 if the vault opened, 1 if it did not, 2 on a usage error.
 *
 * WHAT IT PRINTS
 *   banner   -- the decoy string, always, so that a `strings`-shaped guess has
 *               something to match and you can watch it be wrong.
 *   attempts -- how many times the seed was derived this run.
 *   result   -- the vault contents on success; "refused" otherwise.
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>

int   iv_check_license(const char *license);
int   iv_open_vault(const char *key, char *out, size_t outlen);
int   iv_derive_seed(const char *key);
const char *iv_banner(void);
unsigned iv_attempts(void);

int main(int argc, char **argv)
{
    char out[128];
    int  opened;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <key>\n", argv[0]);
        fprintf(stderr, "  try the obvious one first, then work out why it failed.\n");
        return 2;
    }

    printf("banner   : %s\n", iv_banner());

    /*
     * Deliberate: the runner calls iv_check_license and PRINTS its verdict,
     * but does not act on it. This is the shape of a real decoupled control
     * (chapter 37 lab 04). A hook that flips this return value changes the
     * printed line and changes nothing else -- which is the lesson.
     */
    printf("license  : %s\n",
           iv_check_license(argv[1]) ? "accepted" : "rejected");

    memset(out, 0, sizeof(out));
    opened = iv_open_vault(argv[1], out, sizeof(out));

    printf("attempts : %u\n", iv_attempts());

    if (opened) {
        printf("result   : %s\n", out);
        return 0;
    }

    printf("result   : refused\n");
    return 1;
}
