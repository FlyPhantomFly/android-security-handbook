# 16 — JNI · Cheat Sheet

Printable. Tables and commands only. Full explanations in [`README.md`](README.md).

---

## 1. Type descriptors

| Descriptor | Java | C type | Bytes | Signed? |
|---|---|---|---|---|
| `Z` | `boolean` | `jboolean` | 1 | unsigned (`JNI_TRUE`=1, `JNI_FALSE`=0) |
| `B` | `byte` | `jbyte` | 1 | **signed** (−128..127) |
| `C` | `char` | `jchar` | 2 | **unsigned** UTF-16 unit |
| `S` | `short` | `jshort` | 2 | signed |
| `I` | `int` | `jint` | 4 | signed (`jsize` = `jint`) |
| `J` | `long` | `jlong` | 8 | signed |
| `F` | `float` | `jfloat` | 4 | IEEE 754 |
| `D` | `double` | `jdouble` | 8 | IEEE 754 |
| `V` | `void` | `void` | — | return types only |
| `Lpkg/Class;` | a class | `jobject` | ptr | slashes, trailing `;` |
| `[X` | array of `X` | `jarray` | ptr | one `[` per dimension |

| Java | Descriptor |
|---|---|
| `int[]` | `[I` |
| `int[][][]` | `[[[I` |
| `byte[]` | `[B` |
| `String` | `Ljava/lang/String;` |
| `String[]` | `[Ljava/lang/String;` |
| `Object` | `Ljava/lang/Object;` |
| `android.content.Context` | `Landroid/content/Context;` |
| `com.example.Outer$Inner` | `Lcom/example/Outer$Inner;` |
| varargs `T...` | `[LT;` — varargs *is* an array |

**Method signature:** `(params with no separators)return`

| Java | Signature |
|---|---|
| `void f()` | `()V` |
| `int f()` | `()I` |
| `void f(int,int)` | `(II)V` |
| `String f(String)` | `(Ljava/lang/String;)Ljava/lang/String;` |
| `byte[] f(byte[],int)` | `([BI)[B` |
| `boolean f(int,byte[],String)` | `(I[BLjava/lang/String;)Z` |
| constructor | name `<init>`, return `V` |
| static initialiser | name `<clinit>`, `()V` |

---

## 2. Name mangling

```text
symbol = "Java_" + mangle(FQCN) + "_" + mangle(method)
                 + [ "__" + mangle(param descriptors) ]     <- overloads only
```

| Character | Encoded as |
|---|---|
| `.` or `/` (package separator) | `_` |
| `_` (literal) | `_1` |
| `;` | `_2` |
| `[` | `_3` |
| any other non-ASCII-alphanumeric, UTF-16 unit `U+XXXX` | `_0` + **four** lowercase hex digits |
| `$` (U+0024) | `_00024` |

**The long name omits the return type.** A symbol never tells you what a method returns.

| Java | Symbol |
|---|---|
| `com.example.Crypto.decrypt` | `Java_com_example_Crypto_decrypt` |
| `com.my_app.Guard.check_root` | `Java_com_my_1app_Guard_check_1root` |
| `com.example.Outer$Inner.compute` | `Java_com_example_Outer_00024Inner_compute` |
| `Codec.write(int)` overloaded | `Java_..._Codec_write__I` |
| `Codec.write(byte[])` | `Java_..._Codec_write___3B` (three underscores) |
| `Codec.write(byte[],int,int)` | `Java_..._Codec_write___3BII` |
| `Codec.log(String)` | `Java_..._Codec_log__Ljava_lang_String_2` |
| `A.f_(int)` | `Java_..._A_f_1__I` |

**Demangling order:** strip `Java_`, decode escapes **first**, *then* split on the unescaped `__`.
The last remaining separator splits class from method.

```bash
# host
python3 scripts/jni_mangle.py --mangle 'com.example.Codec.write([BII)V'
python3 scripts/jni_mangle.py --demangle Java_com_example_Codec_write___3BII
python3 scripts/jni_mangle.py --parse '(I[BLjava/lang/String;)Z' --static
python3 scripts/jni_mangle.py --selftest
```

---

## 3. The calling convention

| Slot | Instance method | Static method | `@CriticalNative` |
|---|---|---|---|
| `args[0]` | `JNIEnv *` | `JNIEnv *` | **first real argument** |
| `args[1]` | `jobject` (receiver) | `jclass` (declaring class) | second real argument |
| `args[2]` | **first declared parameter** | **first declared parameter** | third |
| `args[3]` | second declared parameter | second | fourth |
| `args[n]` | parameter `n−1` | parameter `n−1` | parameter `n+1` |

| ABI | Integer/pointer argument registers | Return |
|---|---|---|
| ARM64 | `x0 x1 x2 x3 x4 x5 x6 x7`, then stack | `x0` |
| ARM32 | `r0 r1 r2 r3`, then stack | `r0` (`r0:r1` for 64-bit) |
| x86-64 | `rdi rsi rdx rcx r8 r9`, then stack | `rax` |

Floating-point arguments use `v0`–`v7` (ARM64) / `xmm0`–`xmm7` (x86-64) and are **not** in the
integer `args[]` sequence.

---

## 4. Registration

| | Static | Dynamic |
|---|---|---|
| Mechanism | `dlsym` on the mangled name, at first call | `RegisterNatives(env, cls, table, n)` |
| Symbol in `.dynsym`? | yes | usually no |
| Visible to `nm -D`? | yes | no |
| Class name survives obfuscation? | **forced to** | no — free to be renamed |
| Recoverable statically? | trivially | only by reading `JNI_OnLoad` |
| Recoverable at runtime? | yes | yes — hook `RegisterNatives` |
| Binding time | first call of the method | during `JNI_OnLoad` / `loadLibrary` |

```c
typedef struct { const char* name; const char* signature; void* fnPtr; } JNINativeMethod;
/* 24 bytes on 64-bit, 12 on 32-bit */
```

ART checks: class exists, a method with that **exact** name and signature exists, it is `native`.
ART does **not** check `fnPtr` at all. Re-registration is legal and overwrites.

Lookup order for static registration: **short name first**, then the long name with the argument
suffix. The `UnsatisfiedLinkError` message prints both.

---

## 5. `JNIEnv` vs `JavaVM`

| | `JavaVM *` | `JNIEnv *` |
|---|---|---|
| Scope | one per process | one per **thread** |
| Share between threads | **yes** | **never** |
| Cache in a global | **yes** | **no** |
| Get it from | `JNI_OnLoad` arg 1, or `GetJavaVM` | native method arg 1, `GetEnv`, `AttachCurrentThread` |
| Functions | ~8 | ~230 |

```c
static JavaVM *g_vm;                       /* cache this */
JNIEnv *env;
jint rc = (*g_vm)->GetEnv(g_vm, (void**)&env, JNI_VERSION_1_6);
if (rc == JNI_EDETACHED) { (*g_vm)->AttachCurrentThread(g_vm, &env, NULL); /* ...detach later */ }
```

---

## 6. Reference kinds

| Kind | Created by | Dies at | Cross-thread? | Survives return? |
|---|---|---|---|---|
| **Local** | every object-returning JNI call, every object argument | method return, `DeleteLocalRef`, `PopLocalFrame` | no | no |
| **Global** | `NewGlobalRef` | `DeleteGlobalRef` | yes | yes |
| **Weak global** | `NewWeakGlobalRef` | `DeleteWeakGlobalRef`, or GC | yes | yes, may be null |

| `GetObjectRefType` | Constant |
|---|---|
| 0 | `JNIInvalidRefType` |
| 1 | `JNILocalRefType` |
| 2 | `JNIGlobalRefType` |
| 3 | `JNIWeakGlobalRefType` |

| Limit | Value |
|---|---|
| Guaranteed by the JNI spec without asking | **16** |
| ART default local reference cap | **512 per thread** (abort message states it) |
| Exceeding it | `JNI ERROR (app bug): local reference table overflow (max=512)` — **process abort** |

| Rule | Do not |
|---|---|
| identity | compare with `==` — use `IsSameObject` |
| storage | put a local ref in a `static` |
| threads | pass a local ref to another thread |
| value | treat a `jobject` as an address |
| weak | use without promoting via `NewLocalRef` |
| global | forget `DeleteGlobalRef` |

Fixes for a leaking loop:

```c
(*env)->DeleteLocalRef(env, obj);                       /* per iteration */
(*env)->PushLocalFrame(env, 16); ... (*env)->PopLocalFrame(env, NULL);
(*env)->EnsureLocalCapacity(env, n);                    /* when you truly need many */
```

---

## 7. Strings

| Call | Gives | Encoding | Release with |
|---|---|---|---|
| `GetStringChars` | `const jchar *` | UTF-16, no terminator | `ReleaseStringChars` |
| `GetStringUTFChars` | `const char *` | **modified UTF-8**, NUL-terminated | `ReleaseStringUTFChars` |
| `GetStringRegion` | copies to your `jchar` buffer | UTF-16 | — |
| `GetStringUTFRegion` | copies to your `char` buffer | modified UTF-8 | — |
| `GetStringCritical` | `const jchar *`, may be unpinned | UTF-16 | `ReleaseStringCritical` **immediately** |

| Length call | Returns |
|---|---|
| `GetStringLength` | **UTF-16 code units** |
| `GetStringUTFLength` | **modified UTF-8 bytes** |

**Modified UTF-8:** U+0000 is `0xC0 0x80`; astral characters are two three-byte surrogate sequences.
Never contains a zero byte. Not valid standard UTF-8.

**Size buffers from `GetStringUTFLength`.** Sizing from `GetStringLength` overflows on any non-ASCII
input — up to 3 bytes per unit.

---

## 8. Arrays

| Release mode | Value | Copy back? | Free? |
|---|---|---|---|
| `0` | 0 | yes | yes |
| `JNI_COMMIT` | 1 | yes | no |
| `JNI_ABORT` | 2 | **no** | yes |

`JNI_ABORT` cannot undo writes to a **pinned** (non-copied) array. Never treat it as a rollback.

| Situation | Use |
|---|---|
| small, read-only | `Get<T>ArrayRegion` into a stack buffer, after checking the length |
| large, read-only | `Get<T>ArrayElements` + `JNI_ABORT` |
| modify in place | `Get<T>ArrayElements` + mode `0` |
| tiny hot window | `GetPrimitiveArrayCritical`, nothing but `memcpy` inside |

`Get/Set<T>ArrayRegion` bounds-check **their own** start/length against the array. They cannot check
your destination buffer. `GetArrayLength` is free and authoritative — a separately passed length is
a hint.

---

## 9. Exceptions

**JNI does not unwind.** A failure sets a pending exception on the thread and returns normally.

Legal with an exception pending — and nothing else:

| `ExceptionCheck` | `ExceptionOccurred` | `ExceptionDescribe` | `ExceptionClear` |
|---|---|---|---|
| `DeleteLocalRef` | `DeleteGlobalRef` | `DeleteWeakGlobalRef` | `PopLocalFrame` |
| `MonitorExit` | `Release*` family | `Throw` | `ThrowNew` |

```c
if ((*env)->ExceptionCheck(env)) {
    jthrowable e = (*env)->ExceptionOccurred(env);
    (*env)->ExceptionClear(env);            /* clear FIRST */
    /* ... now other JNI calls are legal ... */
    (*env)->DeleteLocalRef(env, e);
}

/* raising: throw, then RETURN on the next line */
jclass ex = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
if (ex != NULL) { (*env)->ThrowNew(env, ex, "bad"); (*env)->DeleteLocalRef(env, ex); }
return;
```

**Review heuristic:** correct JNI code is branch-heavy. Straight-line JNI code is suspicious by shape.

---

## 10. Constants

| Version | Value | | Return code | Value |
|---|---|---|---|---|
| `JNI_VERSION_1_1` | `0x00010001` | | `JNI_OK` | `0` |
| `JNI_VERSION_1_2` | `0x00010002` | | `JNI_ERR` | `-1` |
| `JNI_VERSION_1_4` | `0x00010004` | | `JNI_EDETACHED` | `-2` |
| `JNI_VERSION_1_6` | `0x00010006` | | `JNI_EVERSION` | `-3` |
| `JNI_VERSION_1_8` | `0x00010008` | | `JNI_ENOMEM` | `-4` |
| | | | `JNI_EEXIST` | `-5` |
| | | | `JNI_EINVAL` | `-6` |

| DEX access flag | Value |
|---|---|
| `ACC_STATIC` | `0x0008` |
| `ACC_SYNCHRONIZED` | `0x0020` |
| `ACC_NATIVE` | `0x0100` |

`JNI_OnLoad` returns a **version**, not a status. ART reports JNI 1.6; return `JNI_VERSION_1_6`.

---

## 11. `@FastNative` / `@CriticalNative`

| | Normal | `@FastNative` | `@CriticalNative` |
|---|---|---|---|
| `JNIEnv *` | yes | yes | **no** |
| `jobject`/`jclass` | yes | yes | **no** |
| Thread state transition | yes | no | no |
| GC can run during | yes | no | no |
| Parameter types | any | any | primitives only |
| Must be static | no | no | **yes** |
| Can call JNI | yes | yes | **no** |

```bash
# host — find them
grep -rn "optimization/CriticalNative\|optimization/FastNative" smali*/
```

---

## 12. The `JNINativeInterface` table, complete

Byte offset = index × 8 (64-bit) or index × 4 (32-bit). Order fixed by the JNI specification.

| # | Function | 64-bit | 32-bit |
|---|---|---|---|
| 0 | `reserved0` | `0x0` | `0x0` |
| 1 | `reserved1` | `0x8` | `0x4` |
| 2 | `reserved2` | `0x10` | `0x8` |
| 3 | `reserved3` | `0x18` | `0xc` |
| 4 | `GetVersion` | `0x20` | `0x10` |
| 5 | `DefineClass` | `0x28` | `0x14` |
| 6 | `FindClass` | `0x30` | `0x18` |
| 7 | `FromReflectedMethod` | `0x38` | `0x1c` |
| 8 | `FromReflectedField` | `0x40` | `0x20` |
| 9 | `ToReflectedMethod` | `0x48` | `0x24` |
| 10 | `GetSuperclass` | `0x50` | `0x28` |
| 11 | `IsAssignableFrom` | `0x58` | `0x2c` |
| 12 | `ToReflectedField` | `0x60` | `0x30` |
| 13 | `Throw` | `0x68` | `0x34` |
| 14 | `ThrowNew` | `0x70` | `0x38` |
| 15 | `ExceptionOccurred` | `0x78` | `0x3c` |
| 16 | `ExceptionDescribe` | `0x80` | `0x40` |
| 17 | `ExceptionClear` | `0x88` | `0x44` |
| 18 | `FatalError` | `0x90` | `0x48` |
| 19 | `PushLocalFrame` | `0x98` | `0x4c` |
| 20 | `PopLocalFrame` | `0xa0` | `0x50` |
| 21 | `NewGlobalRef` | `0xa8` | `0x54` |
| 22 | `DeleteGlobalRef` | `0xb0` | `0x58` |
| 23 | `DeleteLocalRef` | `0xb8` | `0x5c` |
| 24 | `IsSameObject` | `0xc0` | `0x60` |
| 25 | `NewLocalRef` | `0xc8` | `0x64` |
| 26 | `EnsureLocalCapacity` | `0xd0` | `0x68` |
| 27 | `AllocObject` | `0xd8` | `0x6c` |
| 28 | `NewObject` | `0xe0` | `0x70` |
| 29 | `NewObjectV` | `0xe8` | `0x74` |
| 30 | `NewObjectA` | `0xf0` | `0x78` |
| 31 | `GetObjectClass` | `0xf8` | `0x7c` |
| 32 | `IsInstanceOf` | `0x100` | `0x80` |
| 33 | `GetMethodID` | `0x108` | `0x84` |
| 34 | `CallObjectMethod` | `0x110` | `0x88` |
| 35 | `CallObjectMethodV` | `0x118` | `0x8c` |
| 36 | `CallObjectMethodA` | `0x120` | `0x90` |
| 37 | `CallBooleanMethod` | `0x128` | `0x94` |
| 38 | `CallBooleanMethodV` | `0x130` | `0x98` |
| 39 | `CallBooleanMethodA` | `0x138` | `0x9c` |
| 40 | `CallByteMethod` | `0x140` | `0xa0` |
| 41 | `CallByteMethodV` | `0x148` | `0xa4` |
| 42 | `CallByteMethodA` | `0x150` | `0xa8` |
| 43 | `CallCharMethod` | `0x158` | `0xac` |
| 44 | `CallCharMethodV` | `0x160` | `0xb0` |
| 45 | `CallCharMethodA` | `0x168` | `0xb4` |
| 46 | `CallShortMethod` | `0x170` | `0xb8` |
| 47 | `CallShortMethodV` | `0x178` | `0xbc` |
| 48 | `CallShortMethodA` | `0x180` | `0xc0` |
| 49 | `CallIntMethod` | `0x188` | `0xc4` |
| 50 | `CallIntMethodV` | `0x190` | `0xc8` |
| 51 | `CallIntMethodA` | `0x198` | `0xcc` |
| 52 | `CallLongMethod` | `0x1a0` | `0xd0` |
| 53 | `CallLongMethodV` | `0x1a8` | `0xd4` |
| 54 | `CallLongMethodA` | `0x1b0` | `0xd8` |
| 55 | `CallFloatMethod` | `0x1b8` | `0xdc` |
| 56 | `CallFloatMethodV` | `0x1c0` | `0xe0` |
| 57 | `CallFloatMethodA` | `0x1c8` | `0xe4` |
| 58 | `CallDoubleMethod` | `0x1d0` | `0xe8` |
| 59 | `CallDoubleMethodV` | `0x1d8` | `0xec` |
| 60 | `CallDoubleMethodA` | `0x1e0` | `0xf0` |
| 61 | `CallVoidMethod` | `0x1e8` | `0xf4` |
| 62 | `CallVoidMethodV` | `0x1f0` | `0xf8` |
| 63 | `CallVoidMethodA` | `0x1f8` | `0xfc` |
| 64 | `CallNonvirtualObjectMethod` | `0x200` | `0x100` |
| 65 | `CallNonvirtualObjectMethodV` | `0x208` | `0x104` |
| 66 | `CallNonvirtualObjectMethodA` | `0x210` | `0x108` |
| 67 | `CallNonvirtualBooleanMethod` | `0x218` | `0x10c` |
| 68 | `CallNonvirtualBooleanMethodV` | `0x220` | `0x110` |
| 69 | `CallNonvirtualBooleanMethodA` | `0x228` | `0x114` |
| 70 | `CallNonvirtualByteMethod` | `0x230` | `0x118` |
| 71 | `CallNonvirtualByteMethodV` | `0x238` | `0x11c` |
| 72 | `CallNonvirtualByteMethodA` | `0x240` | `0x120` |
| 73 | `CallNonvirtualCharMethod` | `0x248` | `0x124` |
| 74 | `CallNonvirtualCharMethodV` | `0x250` | `0x128` |
| 75 | `CallNonvirtualCharMethodA` | `0x258` | `0x12c` |
| 76 | `CallNonvirtualShortMethod` | `0x260` | `0x130` |
| 77 | `CallNonvirtualShortMethodV` | `0x268` | `0x134` |
| 78 | `CallNonvirtualShortMethodA` | `0x270` | `0x138` |
| 79 | `CallNonvirtualIntMethod` | `0x278` | `0x13c` |
| 80 | `CallNonvirtualIntMethodV` | `0x280` | `0x140` |
| 81 | `CallNonvirtualIntMethodA` | `0x288` | `0x144` |
| 82 | `CallNonvirtualLongMethod` | `0x290` | `0x148` |
| 83 | `CallNonvirtualLongMethodV` | `0x298` | `0x14c` |
| 84 | `CallNonvirtualLongMethodA` | `0x2a0` | `0x150` |
| 85 | `CallNonvirtualFloatMethod` | `0x2a8` | `0x154` |
| 86 | `CallNonvirtualFloatMethodV` | `0x2b0` | `0x158` |
| 87 | `CallNonvirtualFloatMethodA` | `0x2b8` | `0x15c` |
| 88 | `CallNonvirtualDoubleMethod` | `0x2c0` | `0x160` |
| 89 | `CallNonvirtualDoubleMethodV` | `0x2c8` | `0x164` |
| 90 | `CallNonvirtualDoubleMethodA` | `0x2d0` | `0x168` |
| 91 | `CallNonvirtualVoidMethod` | `0x2d8` | `0x16c` |
| 92 | `CallNonvirtualVoidMethodV` | `0x2e0` | `0x170` |
| 93 | `CallNonvirtualVoidMethodA` | `0x2e8` | `0x174` |
| 94 | `GetFieldID` | `0x2f0` | `0x178` |
| 95 | `GetObjectField` | `0x2f8` | `0x17c` |
| 96 | `GetBooleanField` | `0x300` | `0x180` |
| 97 | `GetByteField` | `0x308` | `0x184` |
| 98 | `GetCharField` | `0x310` | `0x188` |
| 99 | `GetShortField` | `0x318` | `0x18c` |
| 100 | `GetIntField` | `0x320` | `0x190` |
| 101 | `GetLongField` | `0x328` | `0x194` |
| 102 | `GetFloatField` | `0x330` | `0x198` |
| 103 | `GetDoubleField` | `0x338` | `0x19c` |
| 104 | `SetObjectField` | `0x340` | `0x1a0` |
| 105 | `SetBooleanField` | `0x348` | `0x1a4` |
| 106 | `SetByteField` | `0x350` | `0x1a8` |
| 107 | `SetCharField` | `0x358` | `0x1ac` |
| 108 | `SetShortField` | `0x360` | `0x1b0` |
| 109 | `SetIntField` | `0x368` | `0x1b4` |
| 110 | `SetLongField` | `0x370` | `0x1b8` |
| 111 | `SetFloatField` | `0x378` | `0x1bc` |
| 112 | `SetDoubleField` | `0x380` | `0x1c0` |
| 113 | `GetStaticMethodID` | `0x388` | `0x1c4` |
| 114 | `CallStaticObjectMethod` | `0x390` | `0x1c8` |
| 115 | `CallStaticObjectMethodV` | `0x398` | `0x1cc` |
| 116 | `CallStaticObjectMethodA` | `0x3a0` | `0x1d0` |
| 117 | `CallStaticBooleanMethod` | `0x3a8` | `0x1d4` |
| 118 | `CallStaticBooleanMethodV` | `0x3b0` | `0x1d8` |
| 119 | `CallStaticBooleanMethodA` | `0x3b8` | `0x1dc` |
| 120 | `CallStaticByteMethod` | `0x3c0` | `0x1e0` |
| 121 | `CallStaticByteMethodV` | `0x3c8` | `0x1e4` |
| 122 | `CallStaticByteMethodA` | `0x3d0` | `0x1e8` |
| 123 | `CallStaticCharMethod` | `0x3d8` | `0x1ec` |
| 124 | `CallStaticCharMethodV` | `0x3e0` | `0x1f0` |
| 125 | `CallStaticCharMethodA` | `0x3e8` | `0x1f4` |
| 126 | `CallStaticShortMethod` | `0x3f0` | `0x1f8` |
| 127 | `CallStaticShortMethodV` | `0x3f8` | `0x1fc` |
| 128 | `CallStaticShortMethodA` | `0x400` | `0x200` |
| 129 | `CallStaticIntMethod` | `0x408` | `0x204` |
| 130 | `CallStaticIntMethodV` | `0x410` | `0x208` |
| 131 | `CallStaticIntMethodA` | `0x418` | `0x20c` |
| 132 | `CallStaticLongMethod` | `0x420` | `0x210` |
| 133 | `CallStaticLongMethodV` | `0x428` | `0x214` |
| 134 | `CallStaticLongMethodA` | `0x430` | `0x218` |
| 135 | `CallStaticFloatMethod` | `0x438` | `0x21c` |
| 136 | `CallStaticFloatMethodV` | `0x440` | `0x220` |
| 137 | `CallStaticFloatMethodA` | `0x448` | `0x224` |
| 138 | `CallStaticDoubleMethod` | `0x450` | `0x228` |
| 139 | `CallStaticDoubleMethodV` | `0x458` | `0x22c` |
| 140 | `CallStaticDoubleMethodA` | `0x460` | `0x230` |
| 141 | `CallStaticVoidMethod` | `0x468` | `0x234` |
| 142 | `CallStaticVoidMethodV` | `0x470` | `0x238` |
| 143 | `CallStaticVoidMethodA` | `0x478` | `0x23c` |
| 144 | `GetStaticFieldID` | `0x480` | `0x240` |
| 145 | `GetStaticObjectField` | `0x488` | `0x244` |
| 146 | `GetStaticBooleanField` | `0x490` | `0x248` |
| 147 | `GetStaticByteField` | `0x498` | `0x24c` |
| 148 | `GetStaticCharField` | `0x4a0` | `0x250` |
| 149 | `GetStaticShortField` | `0x4a8` | `0x254` |
| 150 | `GetStaticIntField` | `0x4b0` | `0x258` |
| 151 | `GetStaticLongField` | `0x4b8` | `0x25c` |
| 152 | `GetStaticFloatField` | `0x4c0` | `0x260` |
| 153 | `GetStaticDoubleField` | `0x4c8` | `0x264` |
| 154 | `SetStaticObjectField` | `0x4d0` | `0x268` |
| 155 | `SetStaticBooleanField` | `0x4d8` | `0x26c` |
| 156 | `SetStaticByteField` | `0x4e0` | `0x270` |
| 157 | `SetStaticCharField` | `0x4e8` | `0x274` |
| 158 | `SetStaticShortField` | `0x4f0` | `0x278` |
| 159 | `SetStaticIntField` | `0x4f8` | `0x27c` |
| 160 | `SetStaticLongField` | `0x500` | `0x280` |
| 161 | `SetStaticFloatField` | `0x508` | `0x284` |
| 162 | `SetStaticDoubleField` | `0x510` | `0x288` |
| 163 | `NewString` | `0x518` | `0x28c` |
| 164 | `GetStringLength` | `0x520` | `0x290` |
| 165 | `GetStringChars` | `0x528` | `0x294` |
| 166 | `ReleaseStringChars` | `0x530` | `0x298` |
| 167 | `NewStringUTF` | `0x538` | `0x29c` |
| 168 | `GetStringUTFLength` | `0x540` | `0x2a0` |
| 169 | `GetStringUTFChars` | `0x548` | `0x2a4` |
| 170 | `ReleaseStringUTFChars` | `0x550` | `0x2a8` |
| 171 | `GetArrayLength` | `0x558` | `0x2ac` |
| 172 | `NewObjectArray` | `0x560` | `0x2b0` |
| 173 | `GetObjectArrayElement` | `0x568` | `0x2b4` |
| 174 | `SetObjectArrayElement` | `0x570` | `0x2b8` |
| 175 | `NewBooleanArray` | `0x578` | `0x2bc` |
| 176 | `NewByteArray` | `0x580` | `0x2c0` |
| 177 | `NewCharArray` | `0x588` | `0x2c4` |
| 178 | `NewShortArray` | `0x590` | `0x2c8` |
| 179 | `NewIntArray` | `0x598` | `0x2cc` |
| 180 | `NewLongArray` | `0x5a0` | `0x2d0` |
| 181 | `NewFloatArray` | `0x5a8` | `0x2d4` |
| 182 | `NewDoubleArray` | `0x5b0` | `0x2d8` |
| 183 | `GetBooleanArrayElements` | `0x5b8` | `0x2dc` |
| 184 | `GetByteArrayElements` | `0x5c0` | `0x2e0` |
| 185 | `GetCharArrayElements` | `0x5c8` | `0x2e4` |
| 186 | `GetShortArrayElements` | `0x5d0` | `0x2e8` |
| 187 | `GetIntArrayElements` | `0x5d8` | `0x2ec` |
| 188 | `GetLongArrayElements` | `0x5e0` | `0x2f0` |
| 189 | `GetFloatArrayElements` | `0x5e8` | `0x2f4` |
| 190 | `GetDoubleArrayElements` | `0x5f0` | `0x2f8` |
| 191 | `ReleaseBooleanArrayElements` | `0x5f8` | `0x2fc` |
| 192 | `ReleaseByteArrayElements` | `0x600` | `0x300` |
| 193 | `ReleaseCharArrayElements` | `0x608` | `0x304` |
| 194 | `ReleaseShortArrayElements` | `0x610` | `0x308` |
| 195 | `ReleaseIntArrayElements` | `0x618` | `0x30c` |
| 196 | `ReleaseLongArrayElements` | `0x620` | `0x310` |
| 197 | `ReleaseFloatArrayElements` | `0x628` | `0x314` |
| 198 | `ReleaseDoubleArrayElements` | `0x630` | `0x318` |
| 199 | `GetBooleanArrayRegion` | `0x638` | `0x31c` |
| 200 | `GetByteArrayRegion` | `0x640` | `0x320` |
| 201 | `GetCharArrayRegion` | `0x648` | `0x324` |
| 202 | `GetShortArrayRegion` | `0x650` | `0x328` |
| 203 | `GetIntArrayRegion` | `0x658` | `0x32c` |
| 204 | `GetLongArrayRegion` | `0x660` | `0x330` |
| 205 | `GetFloatArrayRegion` | `0x668` | `0x334` |
| 206 | `GetDoubleArrayRegion` | `0x670` | `0x338` |
| 207 | `SetBooleanArrayRegion` | `0x678` | `0x33c` |
| 208 | `SetByteArrayRegion` | `0x680` | `0x340` |
| 209 | `SetCharArrayRegion` | `0x688` | `0x344` |
| 210 | `SetShortArrayRegion` | `0x690` | `0x348` |
| 211 | `SetIntArrayRegion` | `0x698` | `0x34c` |
| 212 | `SetLongArrayRegion` | `0x6a0` | `0x350` |
| 213 | `SetFloatArrayRegion` | `0x6a8` | `0x354` |
| 214 | `SetDoubleArrayRegion` | `0x6b0` | `0x358` |
| 215 | **`RegisterNatives`** | **`0x6b8`** | **`0x35c`** |
| 216 | `UnregisterNatives` | `0x6c0` | `0x360` |
| 217 | `MonitorEnter` | `0x6c8` | `0x364` |
| 218 | `MonitorExit` | `0x6d0` | `0x368` |
| 219 | `GetJavaVM` | `0x6d8` | `0x36c` |
| 220 | `GetStringRegion` | `0x6e0` | `0x370` |
| 221 | `GetStringUTFRegion` | `0x6e8` | `0x374` |
| 222 | `GetPrimitiveArrayCritical` | `0x6f0` | `0x378` |
| 223 | `ReleasePrimitiveArrayCritical` | `0x6f8` | `0x37c` |
| 224 | `GetStringCritical` | `0x700` | `0x380` |
| 225 | `ReleaseStringCritical` | `0x708` | `0x384` |
| 226 | `NewWeakGlobalRef` | `0x710` | `0x388` |
| 227 | `DeleteWeakGlobalRef` | `0x718` | `0x38c` |
| 228 | `ExceptionCheck` | `0x720` | `0x390` |
| 229 | `NewDirectByteBuffer` | `0x728` | `0x394` |
| 230 | `GetDirectBufferAddress` | `0x730` | `0x398` |
| 231 | `GetDirectBufferCapacity` | `0x738` | `0x39c` |
| 232 | `GetObjectRefType` | `0x740` | `0x3a0` |

`JNIInvokeInterface` (the `JavaVM` table) has three reserved slots, then:

| # | Function | 64-bit | 32-bit |
|---|---|---|---|
| 3 | `DestroyJavaVM` | `0x18` | `0xc` |
| 4 | `AttachCurrentThread` | `0x20` | `0x10` |
| 5 | `DetachCurrentThread` | `0x28` | `0x14` |
| 6 | `GetEnv` | `0x30` | `0x18` |
| 7 | `AttachCurrentThreadAsDaemon` | `0x38` | `0x1c` |

---

## 13. Commands

### Static

```bash
# host — what ships
unzip -l app.apk 'lib/*'
unzip -oq app.apk 'lib/*' -d libs

# host — statically registered natives
nm -D --defined-only libs/lib/arm64-v8a/lib*.so | grep ' T Java_'
readelf --dyn-syms -W libs/lib/arm64-v8a/libx.so | grep ' Java_'

# host — dynamic registration indicator
nm -D libs/lib/arm64-v8a/libx.so | grep -E 'JNI_OnLoad|JNI_OnUnload'

# host — the strings that survive dynamic registration
strings -a libx.so | grep -E '^\([A-Z\[L]'                       # signatures
strings -a libx.so | grep -E '^[a-z]+(/[A-Za-z0-9_$]+)+$'        # FindClass names

# host — the Java side
grep -rn "\bnative\b" --include=*.java --include=*.kt .
grep -rn "external fun" --include=*.kt .
grep -rn "System\.loadLibrary\|System\.load\b" --include=*.java --include=*.kt .
apktool d app.apk -o out && grep -rn "^\.method.*\bnative\b" out/smali*/

# host — everything above, in one pass
bash scripts/jni-triage.sh app.apk
```

### Dynamic

```bash
# host — recover dynamic registrations (SPAWN, do not attach)
frida -U -f com.example.app -l scripts/dump-registernatives.js --no-pause

# host — decode arguments from a signature
frida -U -f com.example.app -l scripts/jni-arg-tracer.js --no-pause

# adb shell — CheckJNI as a bug oracle (root)
setprop dalvik.vm.checkjni true
am force-stop com.example.app && am start -n com.example.app/.MainActivity

# host — the logcat filters that matter
adb logcat | grep -E 'UnsatisfiedLinkError|No implementation found|JNI DETECTED ERROR|JNI ERROR|local reference table|dlopen failed'

# adb shell as root — library loads
strace -f -e trace=openat,mmap -p $(pidof com.example.app) 2>&1 | grep '\.so'
```

### Frida snippets

```javascript
// args, always
Interceptor.attach(a, { onEnter(args) {
  const env = args[0], self = args[1], p1 = args[2];   // p1 is the FIRST Java parameter
}});

// jstring -> js
function s(h) { const e = Java.vm.getEnv(), p = e.getStringUtfChars(h, null);
  const v = p.readCString(); e.releaseStringUtfChars(h, p); return v; }

// jbyteArray -> buffer (JNI_ABORT = 2, never write back)
function b(h) { const e = Java.vm.getEnv(), n = e.getArrayLength(h), p = e.getByteArrayElements(h, null);
  const v = Memory.readByteArray(p, n); e.releaseByteArrayElements(h, p, 2); return v; }

// the RegisterNatives slot, version independent
const t = Java.vm.getEnv().handle.readPointer();
const rn = t.add(215 * Process.pointerSize).readPointer();

// every exported Java_* in the process
Process.enumerateModules().forEach(m => m.enumerateExports()
  .filter(e => e.name.startsWith('Java_'))
  .forEach(e => console.log(m.name + ' ' + e.name)));
```

---

## 14. Error message decoder

| Message | Meaning |
|---|---|
| `dlopen failed: library "libx.so" not found` | wrong ABI, or not shipped |
| `dlopen failed: cannot locate symbol` | missing dependency, or a namespace-blocked private symbol |
| `No implementation found for <method> (tried A and B)` | static binding failed; **A and B are the exact symbols ART wanted** |
| `JNI_OnLoad returned bad version` | `JNI_OnLoad` returned something unsupported |
| `local reference table overflow (max=512)` | leaked local refs in a loop — **process abort** |
| `JNI ... called with pending exception` | missing `ExceptionCheck` |
| `native thread has not been attached` | `JNIEnv` used on an unattached thread |
| `accessed stale local reference` | local ref used after return, or on the wrong thread |
| `input is not valid Modified UTF-8` | `NewStringUTF` with bad bytes |
| `NoSuchMethodError` from `RegisterNatives` | the name or signature does not match, exactly |

---

## 15. Security one-liners

| Check | Question |
|---|---|
| Trusted length | Does the native code call `GetArrayLength`, or trust a `jint`? |
| String sizing | Is the buffer sized from `GetStringUTFLength` or `GetStringLength`? |
| Exception discipline | Is there a branch after each fallible JNI call? |
| Local refs | Is there an object-producing call inside a loop with no `DeleteLocalRef`? |
| Handles | Does a `native` method take a `long` that is cast to a pointer? |
| Direct buffers | Is `NewDirectByteBuffer`'s capacity derived from input? |
| Critical regions | Is there anything between `GetPrimitiveArrayCritical` and its release? |
| Reachability | Is the native method reachable by reflection, bypassing the Java wrapper? |
| Hardening | Canary, RELRO, PIE, fortify — see `15-Native-Code/` |
