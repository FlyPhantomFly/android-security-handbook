/*
 * plt-got-hook.c — intercept a library's imported function by swapping one
 *                  pointer, with no code patching at all.
 *
 * WHAT IT DOES
 *   Walks libguard.so's loaded ELF structures at runtime, finds the
 *   R_AARCH64_JUMP_SLOT relocation for the imported symbol `strcmp`, and
 *   overwrites the GOT slot that relocation points at. From that moment,
 *   guard_check's call to strcmp lands in this file's function instead.
 *
 *   Then it calls strcmp() from the HOST binary and shows the host's call is
 *   unaffected — which is the whole trade-off of this hook type in one line.
 *
 * THE MECHANISM, IN ONE PARAGRAPH
 *   A shared library cannot know at link time where libc will be loaded, so a
 *   call to an imported function does not encode libc's address. It branches to
 *   a small stub in .plt, which loads a function pointer out of a writable table
 *   (.got.plt) and branches to that. The dynamic linker fills the table in — at
 *   load time with DT_BIND_NOW / full RELRO, lazily on first call otherwise. The
 *   table is data, and data is easy to change. Overwrite the slot and every
 *   subsequent call from THAT LIBRARY goes wherever you point it. No page
 *   permissions to juggle, no instructions to relocate, no cache to flush.
 *
 * MEASURED, Android 13 / API 33 arm64, unrooted shell:
 *
 *   load base = 0x7138348000
 *   DT_JMPREL entries = 3
 *     [0] type=1026 sym=__cxa_finalize  slot=0x713834a978
 *     [1] type=1026 sym=__cxa_atexit    slot=0x713834a980
 *     [2] type=1026 sym=strcmp          slot=0x713834a988
 *       -> slot currently 0x73cb0e1280 ; overwriting with 0x73cee21f98
 *
 *   guard_check("wrong")   0  ->  1        the library's call was intercepted
 *   host strcmp("a","b")  -1  -> -1        the host's call was NOT
 *
 *   Relocation type 1026 is R_AARCH64_JUMP_SLOT (0x402). If you see 1025
 *   (R_AARCH64_GLOB_DAT) instead, the reference went through .got rather than
 *   .got.plt — the same technique applies, but the entries live under DT_RELA,
 *   not DT_JMPREL.
 *
 * WHY YOU WOULD CHOOSE THIS OVER AN INLINE HOOK
 *   + No instruction analysis, no relocation, no cache maintenance.
 *   + Reversible by writing the old pointer back. Nothing is destroyed.
 *   + Scoped: it affects one library, which is often exactly what you want when
 *     the app and its RASP SDK both call the same libc function.
 *
 * WHY YOU WOULD NOT
 *   - It only works for CROSS-MODULE calls that went through the PLT. A call to
 *     a function defined in the same library is a direct branch and there is no
 *     slot to swap. That is the reason an inline hook exists at all.
 *   - Full RELRO (DT_BIND_NOW plus PT_GNU_RELRO) makes .got.plt read-only after
 *     relocation, so you need mprotect first. This file calls mprotect
 *     unconditionally for that reason.
 *   - It is trivially detectable: a pointer that does not fall inside any
 *     mapped library's range is a loud signal. See ../README.md section 5.
 *
 * HOW TO RUN
 *   ./build-hook-fixtures.sh
 *   adb push $OUT/plt-got-hook $OUT/libguard.so /data/local/tmp/
 *   adb shell chmod 755 /data/local/tmp/plt-got-hook
 *   adb shell /system/bin/linker64 /data/local/tmp/plt-got-hook
 *
 * REQUIREMENTS
 *   Android NDK, arm64 device, adb. No root, no frida-server.
 *
 * WHAT THIS WILL *NOT* TELL YOU
 *   - Whether the target actually imports the symbol you care about. If the
 *     compiler turned strcmp into inline comparisons, or the library statically
 *     linked its own copy, there is no slot and this technique has nothing to
 *     grab. Check with: llvm-readelf --relocs libguard.so | grep JUMP_SLOT
 *   - Whether some OTHER library also calls the function. Each loaded library
 *     has its own GOT. Hooking one does not hook the rest, and that asymmetry
 *     is a feature until the call you care about comes from a library you did
 *     not patch.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <unistd.h>
#include <sys/mman.h>

typedef int (*guard_fn)(const char *);

static int (*real_strcmp)(const char *, const char *) = NULL;

static int fake_strcmp(const char *a, const char *b) {
    printf("    [plt] strcmp(\"%s\", \"%s\") intercepted -> forcing 0 (equal)\n", a, b);
    return 0;
}

struct module { const char *soname; ElfW(Addr) base; const ElfW(Dyn) *dyn; };

/*
 * Some linkers store DT_STRTAB/DT_SYMTAB/DT_JMPREL as link-time virtual
 * addresses and some store them already rebased. Rather than guess, treat any
 * value below the load base as a vaddr that still needs the base added.
 */
#define REBASE(m, v) \
    (((ElfW(Addr))(v) < (m)->base) ? ((m)->base + (ElfW(Addr))(v)) : (ElfW(Addr))(v))

static int find_module(struct dl_phdr_info *info, size_t sz, void *arg) {
    (void)sz;
    struct module *m = arg;
    if (!info->dlpi_name || !strstr(info->dlpi_name, m->soname)) return 0;
    m->base = info->dlpi_addr;
    for (int i = 0; i < info->dlpi_phnum; i++)
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC)
            m->dyn = (const ElfW(Dyn) *)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
    return 1;   /* stop iterating */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    long ps = sysconf(_SC_PAGESIZE);

    void *h = dlopen("/data/local/tmp/libguard.so", RTLD_NOW);
    if (!h) { printf("dlopen failed: %s\n", dlerror()); return 1; }
    guard_fn guard = (guard_fn)dlsym(h, "guard_check");
    if (!guard) { printf("dlsym failed: %s\n", dlerror()); return 1; }

    printf("== BEFORE ==\n");
    printf("  guard_check(\"wrong\") = %d\n", guard("wrong"));

    struct module m = { "libguard.so", 0, NULL };
    dl_iterate_phdr(find_module, &m);
    if (!m.dyn) { printf("libguard.so has no PT_DYNAMIC (or is not loaded)\n"); return 1; }
    printf("\nload base = %p\n", (void *)m.base);

    const char      *strtab = NULL;
    const ElfW(Sym) *symtab = NULL;
    const ElfW(Rela)*rela   = NULL;
    size_t relasz = 0;

    for (const ElfW(Dyn) *d = m.dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
        case DT_STRTAB:   strtab = (const char *)REBASE(&m, d->d_un.d_ptr); break;
        case DT_SYMTAB:   symtab = (const ElfW(Sym) *)REBASE(&m, d->d_un.d_ptr); break;
        case DT_JMPREL:   rela   = (const ElfW(Rela) *)REBASE(&m, d->d_un.d_ptr); break;
        case DT_PLTRELSZ: relasz = (size_t)d->d_un.d_val; break;
        default: break;
        }
    }
    if (!strtab || !symtab || !rela) { printf("incomplete dynamic section\n"); return 1; }

    size_t n = relasz / sizeof(ElfW(Rela));
    printf("DT_JMPREL entries = %zu\n", n);

    int patched = 0;
    for (size_t i = 0; i < n; i++) {
        uint32_t si = (uint32_t)ELF64_R_SYM(rela[i].r_info);
        const char *name = strtab + symtab[si].st_name;
        void **slot = (void **)(m.base + rela[i].r_offset);
        printf("  [%zu] type=%lu sym=%-16s slot=%p\n",
               i, (unsigned long)ELF64_R_TYPE(rela[i].r_info), name, (void *)slot);

        if (strcmp(name, "strcmp") != 0) continue;

        void *pg = (void *)((uintptr_t)slot & ~(uintptr_t)(ps - 1));
        if (mprotect(pg, (size_t)ps, PROT_READ | PROT_WRITE) != 0) {
            perror("mprotect GOT page"); return 1;
        }
        real_strcmp = *slot;
        printf("      -> slot currently %p ; overwriting with %p\n",
               *slot, (void *)(uintptr_t)fake_strcmp);
        *slot = (void *)(uintptr_t)fake_strcmp;
        mprotect(pg, (size_t)ps, PROT_READ);     /* put it back read-only */
        patched = 1;
    }
    if (!patched) { printf("\nno strcmp JUMP_SLOT found - nothing to hook\n"); return 1; }

    printf("\n== AFTER (GOT slot swapped, not one instruction changed) ==\n");
    printf("  guard_check(\"wrong\")  = %d   <- the library's call was redirected\n",
           guard("wrong"));
    printf("  host strcmp(\"a\",\"b\") = %d  <- this process's OWN call was not\n",
           strcmp("a", "b"));
    printf("\n  That asymmetry is the defining property of a PLT/GOT hook: it is\n"
           "  scoped to one module's import table, not to the function itself.\n");
    return 0;
}
