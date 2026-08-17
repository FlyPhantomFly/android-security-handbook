# =============================================================================
#  ClassLoaderHijack.smali  —  Chapter 11, Android Runtime
# =============================================================================
#
#  WHAT THIS FILE IS
#  -----------------
#  This is Smali: the human-readable assembly language for Dalvik bytecode, the
#  instruction set that ART executes. When you decompile an APK with apktool you
#  get files exactly like this one. This file shows what dynamic DEX loading
#  looks like AFTER compilation - i.e. what you will actually be staring at when
#  you reverse a packed or plugin-based app, because in a packed app the Java
#  source does not exist and JADX often fails on the interesting parts.
#
#  It is the compiled form of roughly this Java:
#
#      DexClassLoader cl = new DexClassLoader(dexPath, null, null,
#                                             ctx.getClassLoader());
#      Class<?> c = cl.loadClass("com.example.payload.Greeter");
#      Object o = c.newInstance();
#      Method m = c.getDeclaredMethod("greet", String.class);
#      return (String) m.invoke(o, "smali");
#
#  Every instruction is annotated with what it does and which register holds
#  what, so that a reader who has never seen bytecode can follow it line by line.
#
#  HOW TO RUN IT
#  -------------
#  Smali is not run directly - it is assembled into a DEX and then either put
#  into an APK or loaded by an app. Full round trip:
#
#      # host shell - assemble this single file into a DEX
#      mkdir -p /tmp/smali-in/com/example/runtimelab
#      cp ClassLoaderHijack.smali /tmp/smali-in/com/example/runtimelab/Stage1.smali
#      java -jar smali.jar assemble /tmp/smali-in -o /tmp/stage1.dex
#      # inspect what you produced
#      java -jar baksmali.jar disassemble /tmp/stage1.dex -o /tmp/smali-out
#
#  Or, the way you will meet it in practice - inside a real APK:
#
#      # host shell
#      apktool d target.apk -o out/
#      grep -rn "Ldalvik/system/DexClassLoader;" out/
#      # ...edit the smali...
#      apktool b out/ -o patched.apk
#      apksigner sign --ks debug.keystore patched.apk
#      adb install -r patched.apk
#
#  PREREQUISITES
#  -------------
#   - smali/baksmali (https://github.com/google/smali) or apktool, plus a JRE.
#   - apksigner from the Android SDK build-tools if you rebuild an APK: Android
#     will not install an unsigned or badly-signed APK.
#
#  HOW TO READ SMALI IN 90 SECONDS
#  --------------------------------
#   * Registers are named vN (locals) and pN (parameters). `.locals 9` declares
#     v0..v8; the parameters are then appended after them, so in a static method
#     with two parameters p0 and p1 are physically v9 and v10. baksmali prints
#     them as pN purely to make the listing readable.
#   * Types are JVM descriptors: Ljava/lang/String; is String, [B is byte[],
#     [Ljava/lang/Class; is Class[], V is void, I is int, Z is boolean.
#   * A method reference is written Lowner/Class;->name(ArgTypes)ReturnType.
#   * invoke-* does not produce a value into a register by itself. The result
#     sits in a hidden "result register" and you must copy it out with
#     move-result (primitives) or move-result-object (references) on the VERY
#     NEXT instruction. Forgetting that is the #1 beginner bug when patching.
#   * invoke-direct is used for constructors and private methods;
#     invoke-virtual for normal instance methods; invoke-static for statics;
#     invoke-interface for interface methods; invoke-super for super calls.
#   * `new-instance` only ALLOCATES. The object is unusable until a separate
#     invoke-direct to <init> runs on it. Java's `new X(...)` is always these
#     two instructions, and separating them is what allows the neat trick of
#     computing constructor arguments in between.
#
#  WHY A REVERSER CARES ABOUT THIS PARTICULAR PATTERN
#  ---------------------------------------------------
#  The four references below are the fingerprint of dynamic code loading:
#      Ldalvik/system/DexClassLoader;-><init>
#      Ldalvik/system/InMemoryDexClassLoader;-><init>
#      Ljava/lang/ClassLoader;->loadClass
#      Ljava/lang/reflect/Method;->invoke
#  Find them and you have found the seam between the code that shipped in the
#  APK and the code that actually runs. Everything past that seam is invisible
#  to static analysis until you get the second-stage DEX - see
#  ./hook-classloaders.js in this folder for how to grab it at runtime.
# =============================================================================

.class public Lcom/example/runtimelab/Stage1;
.super Ljava/lang/Object;
.source "Stage1.java"

# .source is metadata only: it records the original file name for stack traces.
# Obfuscators routinely strip or forge it, so never trust it as evidence.


# -----------------------------------------------------------------------------
#  Static field holding the name of the class we intend to pull out of the
#  second-stage DEX.
#
#  REVERSING NOTE: a `static final String` like this is normally INLINED by the
#  compiler at every use site as a plain const-string, so in genuine d8 output
#  you would usually not see the field read at all. It is written out longhand
#  here so that you can recognise sget-object when a real app does keep the
#  field - which packers often do, because they decrypt the name at runtime and
#  store it here instead of shipping it as a literal.
# -----------------------------------------------------------------------------
.field private static final PAYLOAD_CLASS:Ljava/lang/String; = "com.example.payload.Greeter"


# -----------------------------------------------------------------------------
#  Default constructor. Every non-abstract class has one unless it declares
#  another. `.locals 0` means zero local registers; p0 is `this`.
# -----------------------------------------------------------------------------
.method public constructor <init>()V
    .locals 0

    # Chain up to Object's constructor. Constructors are always invoke-direct,
    # never invoke-virtual: they are not dispatched dynamically.
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# =============================================================================
#  loadAndRun - the file-backed DexClassLoader path
#
#  Signature: (Landroid/content/Context;Ljava/lang/String;)Ljava/lang/String;
#      p0 = ctx      : the app Context, used only to obtain the parent loader
#      p1 = dexPath  : absolute path to a .dex/.jar/.apk on disk
#  returns the String that the payload's greet() method produced.
#
#  `.locals 9` -> v0..v8 available. Since this method is STATIC, p0 and p1 are
#  the 10th and 11th registers (v9 and v10). Total register count is 11, which
#  is what the `registers_size` field of the DEX method will say.
# =============================================================================
.method public static loadAndRun(Landroid/content/Context;Ljava/lang/String;)Ljava/lang/String;
    .locals 9
    .param p0, "ctx"        # Landroid/content/Context;
    .param p1, "dexPath"    # Ljava/lang/String;

    # -- Build the loader ------------------------------------------------------

    # ALLOCATE a DexClassLoader into v0. Uninitialised until <init> runs; the
    # verifier will reject any use of v0 before that call.
    new-instance v0, Ldalvik/system/DexClassLoader;

    # v1 = null  -> the `optimizedDirectory` parameter.
    #   const/4 encodes a 4-bit signed literal, so it is the cheapest way to
    #   materialise 0. In a reference-typed slot, 0 means null.
    #   API NOTE: optimizedDirectory has been deprecated and IGNORED since
    #   API 26. Old apps pass getDir("dex", 0) here; seeing that is a good hint
    #   that the code (or the SDK that generated it) is old.
    const/4 v1, 0x0

    # v2 = null  -> the `librarySearchPath` parameter (extra .so directories for
    #   classes loaded by this loader). Non-null here is worth investigating: it
    #   means the second stage also brings native code.
    const/4 v2, 0x0

    # v3 = ctx.getClassLoader()  -> the PARENT loader.
    #   This is the single most important argument. Because of parent
    #   delegation, the parent is asked for every class first. Passing the app's
    #   own loader lets the payload see android.* and the app's own classes.
    #   Passing null would make the boot loader the parent, isolating the
    #   payload from the app's classes - some plugin frameworks do exactly that
    #   on purpose.
    invoke-virtual {p0}, Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;

    # The call's return value lives in the hidden result register; copy it out
    # immediately. `-object` because a ClassLoader is a reference.
    move-result-object v3

    # RUN the constructor on the object allocated in v0.
    #   Argument order matches the descriptor exactly:
    #     v0 = the new object (the implicit `this`)
    #     p1 = dexPath            (Ljava/lang/String;)
    #     v1 = optimizedDirectory (Ljava/lang/String;)  = null
    #     v2 = librarySearchPath  (Ljava/lang/String;)  = null
    #     v3 = parent             (Ljava/lang/ClassLoader;)
    #   Five registers is the maximum for the non-range invoke form; a sixth
    #   would force the compiler to emit invoke-direct/range instead.
    #
    #   *** THIS IS THE INSTRUCTION TO BREAKPOINT ***  Everything the app is
    #   about to execute comes from the file named by p1. Hook this constructor
    #   and you own the second stage before a single payload instruction runs.
    invoke-direct {v0, p1, v1, v2, v3}, Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V

    # -- Find the payload class ------------------------------------------------

    # v4 = "com.example.payload.Greeter"
    #   const-string loads a reference to an entry in the DEX string pool. In a
    #   packed app this is usually NOT a literal: expect the name to arrive from
    #   a decryption routine, so a plain `grep` for the class name finds nothing.
    const-string v4, "com.example.payload.Greeter"

    # v5 = v0.loadClass(v4)
    #   loadClass is declared on java.lang.ClassLoader; the compiler wrote the
    #   owner as DexClassLoader because that is the static type of the variable
    #   in the source. Virtual dispatch resolves it up the hierarchy at runtime,
    #   so both spellings are valid and you will see both in the wild.
    #   Behaviourally this runs parent delegation: ask the parent first, and only
    #   search this loader's own DexPathList if the parent came back empty.
    invoke-virtual {v0, v4}, Ldalvik/system/DexClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object v5

    # -- Instantiate it --------------------------------------------------------

    # v6 = v5.newInstance()
    #   Class.newInstance() calls the public no-argument constructor. It is
    #   deprecated in modern Java in favour of
    #   getDeclaredConstructor().newInstance() because it swallows checked
    #   exceptions, but it is one instruction shorter, so malware and older SDKs
    #   use it constantly. Recognise it on sight.
    invoke-virtual {v5}, Ljava/lang/Class;->newInstance()Ljava/lang/Object;

    move-result-object v6

    # -- Look the method up reflectively --------------------------------------

    # v7 = "greet"  (the method name)
    const-string v7, "greet"

    # Build the parameter-type array: new Class[1] { String.class }
    #   v8 = 1
    const/4 v8, 0x1

    #   v8 = new Class[v8]   (new-array reuses v8 as both size source and
    #                         destination; perfectly legal and very common)
    new-array v8, v8, [Ljava/lang/Class;

    #   v1 = 0  (array index; v1 is reusable now, its null is spent)
    const/4 v1, 0x0

    #   v2 = String.class
    #     const-class materialises a java.lang.Class reference for a type named
    #     in the DEX type pool. Its Java form is `String.class`.
    const-class v2, Ljava/lang/String;

    #   v8[v1] = v2       ->  paramTypes[0] = String.class
    aput-object v2, v8, v1

    # v7 = v5.getDeclaredMethod(v7, v8)
    #   getDeclaredMethod finds methods declared by that exact class, including
    #   non-public ones (getMethod would find only public ones, but would also
    #   search superclasses). Reusing v7 for the result is fine: the name string
    #   has already been consumed as an argument.
    invoke-virtual {v5, v7, v8}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v7

    # -- Call it ---------------------------------------------------------------

    # Build the argument array: new Object[1] { "smali" }
    const/4 v8, 0x1

    new-array v8, v8, [Ljava/lang/Object;

    const/4 v1, 0x0

    const-string v2, "smali"

    aput-object v2, v8, v1

    # v0 = v7.invoke(v6, v8)
    #   Method.invoke(receiver, args). Reusing v0 (which held the loader) for the
    #   result is exactly the kind of register recycling d8 does, and it is why
    #   reading smali requires tracking registers rather than assuming a register
    #   keeps one meaning for the whole method.
    #
    #   *** SECOND BREAKPOINT OF INTEREST ***  This is where control transfers
    #   into code that was never in the APK's classes.dex.
    invoke-virtual {v7, v6, v8}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    # invoke() is declared to return Object, so the compiler inserts a cast to
    # match this method's declared String return type. check-cast throws
    # ClassCastException at runtime if the object is not a String; it does not
    # change the reference.
    check-cast v0, Ljava/lang/String;

    return-object v0
.end method


# =============================================================================
#  loadFromMemory - the InMemoryDexClassLoader path (API 26+, Android 8.0+)
#
#  Signature: ([BLjava/lang/ClassLoader;)Ljava/lang/Class;
#      p0 = dexBytes : the DEX image, already decrypted, as a byte[]
#      p1 = parent   : parent loader
#  returns the loaded Class.
#
#  This is the version that matters for modern packers: nothing is written to
#  disk, so there is no file to pull with `adb pull` and no file for an
#  integrity check or an on-device scanner to see. The bytes exist as a
#  ByteBuffer for a few microseconds and then only as ART's own internal
#  mapping.
# =============================================================================
.method public static loadFromMemory([BLjava/lang/ClassLoader;)Ljava/lang/Class;
    .locals 4
    .param p0, "dexBytes"    # [B
    .param p1, "parent"      # Ljava/lang/ClassLoader;

    # v0 = ByteBuffer.wrap(p0)
    #   invoke-static: no receiver, so the register list contains only the real
    #   arguments. A packer would more often use
    #   ByteBuffer.allocateDirect(...) plus a native memcpy, so that the
    #   plaintext never appears on the Java heap and cannot be recovered from an
    #   hprof dump. Either way it ends up as a ByteBuffer right here.
    invoke-static {p0}, Ljava/nio/ByteBuffer;->wrap([B)Ljava/nio/ByteBuffer;

    move-result-object v0

    # Allocate the loader.
    new-instance v1, Ldalvik/system/InMemoryDexClassLoader;

    # v1.<init>(v0, p1)
    #   Two-argument overload: (ByteBuffer, ClassLoader). There is also a
    #   (ByteBuffer[], ClassLoader) overload for multi-DEX payloads, and newer
    #   platform versions add an overload taking a librarySearchPath. When you
    #   hook this constructor with Frida, hook EVERY overload or you will miss
    #   the multi-DEX case - that is a genuinely common mistake.
    invoke-direct {v1, v0, p1}, Ldalvik/system/InMemoryDexClassLoader;-><init>(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V

    # v2 = Stage1.PAYLOAD_CLASS
    #   sget-object reads a static reference field. See the note on the field
    #   declaration above about why real d8 output usually inlines this.
    sget-object v2, Lcom/example/runtimelab/Stage1;->PAYLOAD_CLASS:Ljava/lang/String;

    # v3 = v1.loadClass(v2)
    invoke-virtual {v1, v2}, Ldalvik/system/InMemoryDexClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object v3

    return-object v3
.end method


# =============================================================================
#  APPENDIX - the grep patterns that find this in a real APK
# =============================================================================
#
#      # host shell, after: apktool d target.apk -o out/
#      grep -rn "Ldalvik/system/DexClassLoader;"          out/
#      grep -rn "Ldalvik/system/InMemoryDexClassLoader;"  out/
#      grep -rn "Ldalvik/system/DelegateLastClassLoader;" out/
#      grep -rn "Ldalvik/system/PathClassLoader;"         out/
#      grep -rn "->loadClass(Ljava/lang/String;)"         out/
#      grep -rn "Ljava/lang/reflect/Method;->invoke"      out/
#      grep -rn "Ljava/lang/Class;->forName"              out/
#
#  ../scripts/find-dynamic-loading.py runs all of these for you, ranks the hits
#  by severity, and falls back to scanning the raw classes*.dex string pool when
#  apktool is not installed or the APK resists unpacking.
#
#  WHAT OBFUSCATION DOES TO THIS LISTING
#  --------------------------------------
#  R8/ProGuard rename YOUR classes and methods but CANNOT rename
#  dalvik.system.DexClassLoader or java.lang.reflect.Method - those are platform
#  types resolved by name at runtime, so the string must survive verbatim in the
#  DEX. Method and class NAMES passed to loadClass/getDeclaredMethod, on the
#  other hand, are just strings and are routinely encrypted, assembled at
#  runtime from a char array, or fetched from a server. So: the CALL SITES stay
#  findable no matter how heavy the obfuscation, while the TARGET NAMES vanish.
#  That asymmetry is why runtime hooking beats static analysis for this specific
#  problem - hook the call site, and the target name is handed to you as an
#  argument.
# =============================================================================
