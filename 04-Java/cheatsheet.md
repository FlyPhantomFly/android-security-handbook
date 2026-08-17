# 04 — Java Cheat Sheet

> Printable reference for [04 — Java](README.md). Tables and commands only.
> Companion chapters: [03 — Programming Fundamentals](../03-Programming-Fundamentals/README.md),
> [05 — Kotlin](../05-Kotlin/README.md), [12 — DEX Internals](../12-DEX-Internals/README.md),
> [56 — JADX](../56-JADX/README.md).

---

## 1. Primitive types, sizes, ranges, descriptors

| Java type | Bits | Range / values | JVM + DEX descriptor | Default | Wrapper class | Smali const opcode |
|---|---|---|---|---|---|---|
| `boolean` | 1 (stored as 8/32) | `true`, `false` | `Z` | `false` | `java.lang.Boolean` | `const/4 v0, 0x1` |
| `byte` | 8 | −128 … 127 | `B` | `0` | `java.lang.Byte` | `const/4`, `const/16` |
| `short` | 16 | −32 768 … 32 767 | `S` | `0` | `java.lang.Short` | `const/16` |
| `char` | 16 | `\u0000` … `\uffff` (0 … 65 535, unsigned) | `C` | `\u0000` | `java.lang.Character` | `const/16` |
| `int` | 32 | −2 147 483 648 … 2 147 483 647 | `I` | `0` | `java.lang.Integer` | `const/4`, `const/16`, `const`, `const/high16` |
| `long` | 64 | −9 223 372 036 854 775 808 … 9 223 372 036 854 775 807 | `J` | `0L` | `java.lang.Long` | `const-wide/16`, `const-wide/32`, `const-wide` |
| `float` | 32 | IEEE-754 single | `F` | `0.0f` | `java.lang.Float` | `const/high16` |
| `double` | 64 | IEEE-754 double | `D` | `0.0d` | `java.lang.Double` | `const-wide/high16` |
| `void` | — | — | `V` | — | `java.lang.Void` | — |

### Reference and array descriptors

| Java | Descriptor | Notes |
|---|---|---|
| `java.lang.String` | `Ljava/lang/String;` | `L` + internal name + `;`; dots become slashes |
| `com.acme.Foo` | `Lcom/acme/Foo;` | Package separator is `/` |
| `int[]` | `[I` | One `[` per dimension |
| `int[][]` | `[[I` | Two dimensions |
| `String[]` | `[Ljava/lang/String;` | Array of references |
| `byte[]` | `[B` | The type of most crypto/IO buffers |
| `Outer.Inner` | `Lcom/acme/Outer$Inner;` | Nesting uses `$` |

### Method descriptors

| Java signature | Descriptor |
|---|---|
| `void main(String[] args)` | `([Ljava/lang/String;)V` |
| `int add(int a, int b)` | `(II)I` |
| `boolean check(String s, byte[] b)` | `(Ljava/lang/String;[B)Z` |
| `long time()` | `()J` |
| `Object invoke(Object o, Object[] a)` | `(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;` |
| constructor `Foo(int)` | `<init>` with `(I)V` |
| static initializer | `<clinit>` with `()V` |

---

## 2. Boxing, caching, and identity

| Expression | Result | Reason |
|---|---|---|
| `Integer a = 127, b = 127; a == b` | `true` | `Integer.valueOf` cache covers −128 … 127 |
| `Integer a = 128, b = 128; a == b` | `false` | Outside cache, two distinct objects |
| `new Integer(1) == new Integer(1)` | `false` | Explicit allocation bypasses cache (constructor deprecated since Java 9) |
| `a.equals(b)` for any equal values | `true` | Compares numeric value |
| `Long`, `Short`, `Byte`, `Character` caches | −128 … 127 (`Character` 0 … 127) | Same `valueOf` pattern |
| `Boolean.valueOf(true) == Boolean.TRUE` | `true` | Only two instances exist |
| `Double`/`Float` caching | none | Never identity-compare boxed floats |
| `"a" == "a"` | `true` | Both are string-pool literals |
| `new String("a") == "a"` | `false` | `new` forces a fresh object |
| `new String("a").intern() == "a"` | `true` | `intern()` returns the pooled instance |

---

## 3. Access modifier visibility matrix

| Modifier | Same class | Same package | Subclass (other package) | Anywhere | Keyword |
|---|---|---|---|---|---|
| `private` | Yes | No | No | No | `private` |
| package-private | Yes | Yes | No | No | *(no keyword)* |
| `protected` | Yes | Yes | Yes | No | `protected` |
| `public` | Yes | Yes | Yes | Yes | `public` |

| Non-access modifier | Applies to | Meaning | Smali / bytecode flag |
|---|---|---|---|
| `static` | field, method, nested class, init block | Belongs to the class, not an instance | `static` |
| `final` | class, method, field, local | No subclass / no override / single assignment | `final` |
| `abstract` | class, method | No body, must be subclassed | `abstract` |
| `synchronized` | method, block | Acquires monitor | `declared-synchronized` / `monitor-enter` |
| `volatile` | field | No caching, happens-before on read/write | `volatile` |
| `transient` | field | Skipped by Java serialization | `transient` |
| `native` | method | Implemented in JNI | `native` |
| `strictfp` | class, method | Strict FP semantics (no-op since Java 17) | `strict` |

> Reminder for the matrix above: after `d8` and `jadx`, every one of these is metadata only. `private` is
> not enforced against a reverse engineer holding the DEX.

---

## 4. String methods and their cost

| Method | Signature | Returns | Notes |
|---|---|---|---|
| `length()` | `()I` | UTF-16 code-unit count | Not the character count for surrogate pairs |
| `charAt(int)` | `(I)C` | one UTF-16 unit | Throws `StringIndexOutOfBoundsException` |
| `equals(Object)` | `(Ljava/lang/Object;)Z` | value equality | The correct comparison |
| `equalsIgnoreCase(String)` | `(Ljava/lang/String;)Z` | case-insensitive | Locale-independent |
| `contentEquals(CharSequence)` | `(Ljava/lang/CharSequence;)Z` | value equality | Works against `StringBuilder` |
| `compareTo(String)` | `(Ljava/lang/String;)I` | lexicographic | Not constant-time |
| `hashCode()` | `()I` | `s[0]*31^(n-1) + …` | Cached in the `hash` field |
| `indexOf(String)` | `(Ljava/lang/String;)I` | index or −1 | |
| `substring(int,int)` | `(II)Ljava/lang/String;` | new `String` | Copies since Java 7u6 |
| `concat(String)` | `(Ljava/lang/String;)Ljava/lang/String;` | new `String` | |
| `split(String)` | `(Ljava/lang/String;)[Ljava/lang/String;` | array | Argument is a regex |
| `replace(CharSequence,CharSequence)` | `(…)Ljava/lang/String;` | new `String` | Literal, not regex |
| `trim()` / `strip()` | `()Ljava/lang/String;` | new `String` | `strip()` is Unicode-aware, Java 11+ |
| `toCharArray()` | `()[C` | `char[]` | Preferred for secrets — can be zeroed |
| `getBytes(Charset)` | `(Ljava/nio/charset/Charset;)[B` | `byte[]` | Always name the charset |
| `format(String,Object…)` | `(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;` | new `String` | |
| `intern()` | `()Ljava/lang/String;` | pooled instance | |
| `isEmpty()` / `isBlank()` | `()Z` | | `isBlank()` is Java 11+ |
| `join(CharSequence,…)` | static | new `String` | |
| `matches(String)` | `(Ljava/lang/String;)Z` | regex match | Compiles the pattern every call |

| Builder | Thread-safe | Use when |
|---|---|---|
| `String` | Immutable, so yes | Fixed text, map keys, constants |
| `StringBuilder` | No | All single-threaded concatenation in loops |
| `StringBuffer` | Yes (synchronized) | Legacy; almost never needed |

---

## 5. Collections comparison

| Type | Backing structure | `get`/`contains` | `add`/`put` | Remove (middle) | Ordered? | Nulls | Thread-safe |
|---|---|---|---|---|---|---|---|
| `ArrayList` | resizable `Object[]` | O(1) index, O(n) search | O(1) amortised | O(n) | insertion order | yes | No |
| `LinkedList` | doubly-linked nodes | O(n) | O(1) at ends | O(1) with iterator | insertion order | yes | No |
| `ArrayDeque` | circular array | O(n) contains | O(1) at both ends | O(n) | insertion order | no nulls | No |
| `HashMap` | bucket array + node/tree | O(1) average, O(log n) treeified | O(1) average | O(1) average | none | 1 null key, many null values | No |
| `LinkedHashMap` | `HashMap` + linked list | O(1) average | O(1) average | O(1) average | insertion or access order | same as `HashMap` | No |
| `TreeMap` | red-black tree | O(log n) | O(log n) | O(log n) | sorted by key | no null key | No |
| `HashSet` | wraps `HashMap` | O(1) average | O(1) average | O(1) average | none | one null | No |
| `LinkedHashSet` | wraps `LinkedHashMap` | O(1) average | O(1) average | O(1) average | insertion order | one null | No |
| `TreeSet` | wraps `TreeMap` | O(log n) | O(log n) | O(log n) | sorted | no null | No |
| `ConcurrentHashMap` | striped/CAS bucket array | O(1) average | O(1) average | O(1) average | none | no nulls at all | Yes |
| `Collections.synchronizedMap` | wrapper + single lock | O(1) average | O(1) average | O(1) average | none | as wrapped | Yes, coarse |
| `CopyOnWriteArrayList` | copies array on write | O(1) index | O(n) per write | O(n) | insertion order | yes | Yes, read-optimised |

### HashMap internals constants

| Constant | Value | Meaning |
|---|---|---|
| `DEFAULT_INITIAL_CAPACITY` | 16 | Bucket array length, always a power of two |
| `DEFAULT_LOAD_FACTOR` | 0.75 | Resize when `size > capacity * loadFactor` |
| `TREEIFY_THRESHOLD` | 8 | Bucket list converts to a red-black tree |
| `UNTREEIFY_THRESHOLD` | 6 | Tree reverts to a list |
| `MIN_TREEIFY_CAPACITY` | 64 | Below this, resize instead of treeify |
| bucket index | `(n - 1) & hash` | Cheap modulo because `n` is a power of two |
| hash spread | `h ^ (h >>> 16)` | Mixes high bits into low bits |

### equals / hashCode contract

| Rule | Consequence if broken |
|---|---|
| `a.equals(b)` implies `a.hashCode() == b.hashCode()` | Lookups miss; `map.get(key)` returns `null` for a key that is in the map |
| Equal hash codes do not require equality | Only a performance property |
| `equals` must be reflexive, symmetric, transitive, consistent | Sets can contain apparent duplicates |
| `x.equals(null)` is `false` | `NullPointerException` at runtime |
| Do not mutate fields used in `hashCode` after insertion | The entry becomes unreachable in its own map |

---

## 6. Generics and type erasure

| Source | After erasure (what is in the DEX) |
|---|---|
| `List<String>` | `Ljava/util/List;` |
| `Map<String,byte[]>` | `Ljava/util/Map;` |
| `<T> T pick(List<T> l)` | `(Ljava/util/List;)Ljava/lang/Object;` |
| `<T extends Number> T f(T t)` | `(Ljava/lang/Number;)Ljava/lang/Number;` |
| `list.get(0)` assigned to `String` | `check-cast Ljava/lang/String;` inserted by the compiler |
| `new T[]` | Illegal — arrays are reified, generics are not |
| `instanceof List<String>` | Illegal — only `instanceof List` |
| Generic signature | Preserved in the `Signature` attribute / `dalvik.annotation.Signature`, which is why JADX can still print `List<String>` |

---

## 7. Exception hierarchy

| Class | Checked? | Catch it? | Typical cause |
|---|---|---|---|
| `java.lang.Throwable` | — | Almost never | Root of everything throwable |
| `java.lang.Error` | Unchecked | No | JVM-level failure |
| `OutOfMemoryError` | Unchecked | No | Heap or bitmap exhaustion |
| `StackOverflowError` | Unchecked | No | Unbounded recursion |
| `NoClassDefFoundError` | Unchecked | Rarely | Class present at compile time, absent at runtime |
| `java.lang.Exception` | Checked | Yes | Recoverable application failure |
| `IOException` | Checked | Yes | File, socket, stream failure |
| `FileNotFoundException` | Checked | Yes | Subclass of `IOException` |
| `ClassNotFoundException` | Checked | Yes | Thrown by `Class.forName` |
| `NoSuchMethodException` | Checked | Yes | Thrown by `getDeclaredMethod` |
| `IllegalAccessException` | Checked | Yes | Reflection without `setAccessible(true)` |
| `InvocationTargetException` | Checked | Yes | Wraps whatever the reflected method threw — unwrap with `getCause()` |
| `InterruptedException` | Checked | Yes | Thread interrupted while blocked |
| `java.lang.RuntimeException` | Unchecked | Selectively | Programming error |
| `NullPointerException` | Unchecked | Fix instead | Dereferencing `null` |
| `ClassCastException` | Unchecked | Fix instead | Bad `check-cast`, often from erased generics |
| `ArrayIndexOutOfBoundsException` | Unchecked | Fix instead | Bad index |
| `NumberFormatException` | Unchecked | Yes at parse boundaries | Subclass of `IllegalArgumentException` |
| `IllegalArgumentException` | Unchecked | Yes at API boundaries | Bad parameter |
| `IllegalStateException` | Unchecked | Yes | Object used in the wrong lifecycle state |
| `ConcurrentModificationException` | Unchecked | Fix instead | Structural modification during iteration |
| `SecurityException` | Unchecked | Yes | Android permission denial surfaces here |

---

## 8. Reflection API

| API | Signature fragment | What it does |
|---|---|---|
| `Class.forName(String)` | `(Ljava/lang/String;)Ljava/lang/Class;` | Loads and initialises a class by name |
| `Class.forName(String,boolean,ClassLoader)` | `(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;` | Same, with explicit loader and init control |
| `obj.getClass()` | `()Ljava/lang/Class;` | Runtime class of an instance |
| `Foo.class` | — | Compile-time class literal, `const-class` in Smali |
| `getDeclaredMethod(String,Class…)` | `(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;` | Any method declared on this class, including `private` |
| `getMethod(String,Class…)` | same | `public` methods, including inherited |
| `getDeclaredMethods()` | `()[Ljava/lang/reflect/Method;` | All declared methods |
| `getDeclaredField(String)` | `(Ljava/lang/String;)Ljava/lang/reflect/Field;` | Any declared field |
| `getField(String)` | same | `public` fields only |
| `getDeclaredConstructor(Class…)` | `([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;` | Any constructor |
| `setAccessible(boolean)` | `(Z)V` | Disables the access check — the loudest reflection signal |
| `Method.invoke(Object,Object…)` | `(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;` | Calls the method; `null` receiver for `static` |
| `Field.get(Object)` / `set(Object,Object)` | `(Ljava/lang/Object;)Ljava/lang/Object;` | Read/write a field |
| `Field.getInt(Object)` etc. | `(Ljava/lang/Object;)I` | Primitive accessors |
| `Constructor.newInstance(Object…)` | `([Ljava/lang/Object;)Ljava/lang/Object;` | Constructs an object |
| `Array.newInstance(Class,int)` | `(Ljava/lang/Class;I)Ljava/lang/Object;` | Builds an array of a runtime type |
| `Proxy.newProxyInstance(…)` | | Dynamic interface implementation |
| `dalvik.system.DexClassLoader` | | Loads a DEX from a path — dynamic code loading |
| `dalvik.system.InMemoryDexClassLoader` | | Loads a DEX from a `ByteBuffer`, leaves no file |
| `dalvik.system.PathClassLoader` | | The app's own loader |

### Reflection grep fingerprints (Smali)

| Pattern | Category |
|---|---|
| `Ljava/lang/Class;->forName(` | Class lookup by name |
| `Ljava/lang/Class;->getDeclaredMethod(` | Private method lookup |
| `Ljava/lang/Class;->getMethod(` | Public method lookup |
| `Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V` | Access-check bypass |
| `Ljava/lang/reflect/Method;->invoke(` | Reflective call |
| `Ljava/lang/reflect/Field;->get` / `->set` | Reflective field access |
| `Ldalvik/system/DexClassLoader;-><init>` | Dynamic code loading |
| `Landroid/util/Base64;->decode(` | Often decodes the hidden class name |
| `Ljava/util/Base64$Decoder;->decode(` | JVM-side equivalent |
| `Ljavax/crypto/Cipher;->doFinal(` near the above | Encrypted string table |

---

## 9. Smali opcode to Java construct

| Smali opcode | Java construct | Notes |
|---|---|---|
| `invoke-virtual` | normal instance method call | Virtual dispatch on the runtime type |
| `invoke-super` | `super.method()` | Skips the override |
| `invoke-direct` | `private` method, or `<init>` | Non-virtual, no dispatch |
| `invoke-static` | `static` method call | No receiver register |
| `invoke-interface` | call through an interface reference | |
| `invoke-polymorphic` | `MethodHandle.invoke` | Rare, API 26+ |
| `invoke-custom` | `invokedynamic` — lambdas, string concat | API 26+; before that, desugared |
| `invoke-*/range` | same, more than 5 argument registers | |
| `new-instance` | `new Foo` (allocation only) | Always followed by an `invoke-direct <init>` |
| `new-array` / `filled-new-array` | `new int[n]` / `new int[]{…}` | |
| `iget`, `iget-object`, `iget-boolean` | read instance field | `i` = instance |
| `iput`, `iput-object`, `iput-wide` | write instance field | |
| `sget`, `sget-object`, `sget-wide` | read static field | `s` = static |
| `sput`, `sput-object` | write static field | |
| `const-string` | string literal | Index into the DEX string table |
| `const-string/jumbo` | string literal, index ≥ 65 536 | |
| `const-class` | `Foo.class` | |
| `check-cast` | `(Foo) x` | Inserted automatically for erased generics |
| `instance-of` | `x instanceof Foo` | |
| `throw` | `throw e` | |
| `move-exception` | first instruction of a `catch` block | |
| `monitor-enter` / `monitor-exit` | `synchronized (x) { }` | Paired; `monitor-exit` also appears on the exception path |
| `return-void`, `return`, `return-object`, `return-wide` | `return` | |
| `if-eqz`, `if-nez`, `if-eq`, `if-ne`, `if-lt` … | `if` | `z` suffix compares against zero/null |
| `goto`, `goto/16`, `goto/32` | loop or `else` jump | |
| `packed-switch`, `sparse-switch` | `switch` | Dense versus scattered case values |
| `array-length` | `arr.length` | |
| `aget`, `aput` (`-object`, `-byte`, …) | `arr[i]` read/write | |
| `fill-array-data` | `new byte[]{1,2,3}` initialiser | Payload sits in a `.array-data` block |
| `cmp-long`, `cmpl-float`, `cmpg-double` | comparing wide primitives | Feeds an `if-*` |

### Exception handling in Smali

```smali
# baksmali output — the shape of try/catch
    :try_start_0
    invoke-static {v0}, Lcom/acme/Net;->fetch(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    goto :goto_0

    :catch_0
    move-exception v2          # the caught Throwable lands here
    const-string v1, "fallback"

    :goto_0
    return-object v1
```

| Element | Meaning |
|---|---|
| `:try_start_N` / `:try_end_N` | Bounds of the protected region |
| `.catch Ltype; {start .. end} :label` | One handler for one exception type |
| `.catchall {start .. end} :label` | `finally`, or `catch (Throwable)` |
| `move-exception vN` | Binds the thrown object to a register |
| Duplicated `finally` code | The compiler inlines `finally` into every exit path |

---

## 10. JADX and compiler naming patterns

| Name you see | Produced by | Meaning |
|---|---|---|
| `Outer$Inner` | any nested class | Static nested or inner class named `Inner` |
| `Outer$1`, `Outer$2` | anonymous class | Nth anonymous class in `Outer`, numbered in source order |
| `Outer$1$1` | anonymous inside anonymous | |
| `this$0` | inner (non-static) class | Synthetic reference to the enclosing instance |
| `val$x` | anonymous/local class | Captured local variable `x`, copied into a synthetic field |
| `this$0` plus `val$` together | inner class capturing locals | |
| `access$000`, `access$100` | javac | Synthetic bridge so an inner class can touch an outer `private` member |
| `lambda$foo$0` | javac lambda desugaring | Lambda body lifted out of method `foo`, index 0 |
| `-$$Lambda$Foo$abc123` | D8 lambda desugaring (older AGP) | Generated lambda class |
| `Foo$$ExternalSyntheticLambda0` | R8/D8 desugaring (newer AGP) | Generated lambda class |
| `Foo$$Lambda$1` | JVM `LambdaMetafactory` at runtime | Not present on disk |
| `synthetic` / `bridge` flags | compiler | Method the programmer never wrote |
| bridge method | generics/covariant returns | `compareTo(Object)` forwarding to `compareTo(Foo)` |
| `Foo$WhenMappings` | Kotlin `when` over enum | See [05 — Kotlin](../05-Kotlin/README.md) |
| `$values`, `values()`, `valueOf()` | `enum` | Compiler-generated enum plumbing |
| `<clinit>` | static initializer | Runs once on first class use |
| `<init>` | constructor | |
| `a`, `b`, `c`, `a.a.a` | ProGuard/R8 | Identifiers were renamed — see [41 — ProGuard](../41-ProGuard/README.md) |
| `p0`, `p1` / `v0`, `v1` | baksmali | Parameter registers and local registers |

---

## 11. Toolchain command reference

### Compile and inspect on the host

```bash
# host — compile, run, inspect Java
javac Hello.java                          # produces Hello.class
javac -g Hello.java                       # keep local variable names + line numbers
javac -d out/ src/com/acme/*.java         # output tree rooted at out/
java Hello                                # run a compiled class
java Hello.java                           # single-file source-launch, JDK 11+
java -cp out com.acme.Main                # run with an explicit classpath
jar cf app.jar -C out .                   # package classes into a jar
```

```bash
# host — read the class file
javap Hello.class                         # public API only
javap -p Hello.class                      # include private members
javap -c Hello.class                      # disassemble bytecode
javap -c -p -v Hello.class                # + constant pool, flags, attributes
javap -s Hello.class                      # print type descriptors
javap -c -p java.lang.String              # works on JDK classes too
xxd Hello.class | head -4                 # magic bytes: cafe babe
```

### DEX conversion

```bash
# host — Java bytecode to DEX (d8 ships in Android SDK build-tools)
d8 Hello.class --output .                 # produces classes.dex
d8 --release --min-api 21 *.class --output out/
d8 --lib "$ANDROID_HOME/platforms/android-34/android.jar" Hello.class --output .
dx --dex --output=classes.dex Hello.class # legacy, removed from modern build-tools
xxd classes.dex | head -4                 # magic bytes: 6465 780a 3033 3500 -> "dex\n035\0"
```

### DEX and APK inspection

```bash
# host — unpack and disassemble
unzip -l app.apk                          # list APK entries
unzip -o app.apk classes.dex -d out/      # extract the primary DEX
apktool d app.apk -o app_out              # resources + smali
apktool d --no-res app.apk -o app_out     # smali only, much faster
apktool b app_out -o rebuilt.apk          # rebuild
baksmali d classes.dex -o smali_out       # DEX to smali
smali a smali_out -o classes.dex          # smali back to DEX
jadx -d jadx_out app.apk                  # decompile to Java
jadx --show-bad-code -d jadx_out app.apk  # keep partially failed methods
jadx --deobf -d jadx_out app.apk          # rename obfuscated identifiers
jadx-gui app.apk                          # interactive
dexdump -d classes.dex                    # AOSP dexdump disassembly
strings -a -n 8 classes.dex               # crude string sweep
python3 scripts/dump-strings.py app.apk --min-len 8 --heuristic   # precise string table
```

### Grep patterns on Smali

```bash
# host — run from the apktool output directory
grep -rn "Ljava/lang/Class;->forName" smali*/
grep -rn "setAccessible" smali*/
grep -rn "Ljava/lang/reflect/Method;->invoke" smali*/
grep -rn "Ldalvik/system/DexClassLoader" smali*/
grep -rn "const-string" smali*/ | grep -Ei "http|api[_-]?key|secret|token|password"
bash scripts/find-reflection.sh app.apk    # all of the above, grouped
```

### Runtime and device

```bash
# host
adb shell pm list packages -f | grep acme          # find the installed APK path
adb pull /data/app/~~abc==/com.acme-1/base.apk .   # pull it
adb logcat -s AndroidRuntime:E                     # stack traces only
```

```bash
# host — JVM-side runtime inspection of your own test classes
java -verbose:class Hello           # every class as it loads
java -Xlog:class+load=info Hello    # JDK 9+ unified logging form
jshell                              # REPL for quick semantics experiments
```

---

## 12. Serialization quick reference

| Element | Purpose | Risk |
|---|---|---|
| `implements Serializable` | Marks a class as JVM-serializable | Every field becomes attacker-reachable state |
| `implements Externalizable` | Manual `writeExternal`/`readExternal` | Full control, still a sink |
| `implements Parcelable` | Android IPC marshalling | Not a persistence format; version-fragile |
| `private static final long serialVersionUID` | Version stamp | If absent, it is computed from the class shape and breaks on any change |
| `transient` | Field is skipped on write, left at default on read | The usual way to keep secrets out of the stream |
| `private void writeObject(ObjectOutputStream)` | Custom write hook | |
| `private void readObject(ObjectInputStream)` | Custom read hook | **Runs before any of your validation** — classic gadget entry point |
| `readResolve()` | Substitute the deserialized object | Needed to keep singletons singular |
| `ObjectInputFilter` (Java 9+) | Allow-list of classes | The supported mitigation |
| `CREATOR` field | Required by `Parcelable` | `createFromParcel` must read fields in the exact write order |

---

## 13. Concurrency quick reference

| Construct | Guarantees | Notes |
|---|---|---|
| `synchronized` method | Mutual exclusion + visibility | Locks `this`, or the `Class` object when static |
| `synchronized (obj)` | Same, explicit monitor | `monitor-enter` / `monitor-exit` in Smali |
| `volatile` field | Visibility + ordering, **not** atomicity | `i++` on a volatile is still a race |
| `final` field | Safe publication after construction | |
| `AtomicInteger` / `AtomicReference` | Atomic read-modify-write | CAS-based |
| `ReentrantLock` | Explicit lock with `tryLock`, fairness | Must unlock in `finally` |
| `ExecutorService` | Managed thread pool | Always `shutdown()` |
| `Executors.newFixedThreadPool(n)` | n reusable threads | |
| `Executors.newSingleThreadExecutor()` | Serialized task execution | |
| `CountDownLatch` | One-shot rendezvous | |
| `Thread.sleep` | Does not release monitors | |
| `Object.wait` / `notify` | Releases the monitor | Must be called inside `synchronized` |
| `ConcurrentHashMap` | Per-bin locking / CAS | Compound operations still need `compute`, `merge`, `putIfAbsent` |

---

## 14. One-line recall prompts

| Prompt | Answer |
|---|---|
| Descriptor for `long` | `J` |
| Descriptor for `boolean` | `Z` |
| Descriptor for `String[]` | `[Ljava/lang/String;` |
| Opcode for calling a `private` method | `invoke-direct` |
| Opcode for a `static` field read | `sget` / `sget-object` |
| Smali marker for a catch block body | `move-exception` |
| Integer cache range | −128 to 127 |
| `HashMap` default capacity and load factor | 16 and 0.75 |
| Bucket-to-tree threshold | 8 nodes with capacity at least 64 |
| Method name of a static initializer | `<clinit>` |
| Reflection call that removes the access check | `setAccessible(true)` |
| Class name pattern for an anonymous class | `Outer$1` |
| Synthetic field holding the enclosing instance | `this$0` |
| Deserialization hook that runs too early | `readObject` |
| DEX file magic | `dex\n035\0` |
| Class file magic | `cafebabe` |
