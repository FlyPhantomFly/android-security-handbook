# Obfuscation — Cheat Sheet

Printable. No prose. See [README.md](README.md) for why each of these works.

---

## Triage — is it protected, and how?

| Check | Command | Verdict |
|---|---|---|
| DEX class count | `python3 -c "import struct;d=open('classes.dex','rb').read(0x70);print(struct.unpack_from('<I',d,0x60)[0])"` | `< 50` → packed stub |
| DEX size vs APK | `unzip -l app.apk \| grep -E 'classes.*dex'` | tiny dex + huge apk → packed |
| Readable URLs | `unzip -p app.apk classes.dex \| strings -n 6 \| grep -c 'https\?://'` | `0` → string encryption |
| Application class | `aapt2 dump xmltree app.apk --file AndroidManifest.xml \| grep -A3 'E: application'` | vendor package → packer stub |
| High-entropy assets | `unzip -l app.apk \| awk '$1>500000{print $1,$4}' \| sort -rn` | big `assets/*.dat` → payload |
| Native libs | `unzip -l app.apk \| grep '\.so$'` | vendor `.so` → runtime protection |
| Anti-analysis strings | `grep -rEl 'ptrace\|TracerPid\|frida\|xposed\|magisk' apktool_out libs` | present → spawn-gate |
| Mapping file shipped | `unzip -l app.apk \| grep -i 'mapping\|\.map'` | present → total disclosure |
| Flattening | open 3 methods in jadx, look for `while(true){switch}` | present → state-table work |
| Kotlin metadata | `grep -rn 'Lkotlin/Metadata;' apktool_out/smali*` | present → free original names |

## DEX header offsets

| Off | Size | Field | Use |
|---|---|---|---|
| 0x00 | 8 | magic `64 65 78 0A vv vv vv 00` | carve signature |
| 0x08 | 4 | checksum (Adler-32) | repair after dump |
| 0x0C | 20 | SHA-1 signature | repair after dump |
| 0x20 | 4 | file_size | how many bytes to carve |
| 0x24 | 4 | header_size = `0x70` | validator |
| 0x28 | 4 | endian_tag = `0x12345678` | validator |
| 0x34 | 4 | map_off | |
| 0x38 | 4 | string_ids_size | string-encryption proxy |
| 0x58 | 4 | method_ids_size | 64K limit |
| 0x60 | 4 | class_defs_size | **packing detector** |

Versions seen: `035` `037` `038` `039` `040` `041`

## Extraction

```bash
adb shell pm path com.target.app            # ALL splits
adb pull <path> .
sha256sum base.apk
apksigner verify --print-certs base.apk
unzip -o base.apk -d ext
jadx -d out --show-bad-code base.apk
apktool d -f -o apktool_out base.apk
aapt2 dump badging base.apk
aapt2 dump xmltree base.apk --file AndroidManifest.xml
```

## Static grep table

| Target | Grep |
|---|---|
| XOR decryptors | `grep -rn 'xor-int' apktool_out/smali*` |
| AES decryptors | `grep -rn 'Ljavax/crypto/Cipher;->getInstance' apktool_out/smali*` |
| Reflection | `grep -rn 'Ljava/lang/Class;->forName\|reflect/Method;->invoke' apktool_out/smali*` |
| Dynamic loading | `grep -rn 'Ldalvik/system/.*ClassLoader;-><init>' apktool_out/smali*` |
| Native loading | `grep -rn 'System;->loadLibrary\|System;->load(' apktool_out/smali*` |
| Flattened candidates | `grep -rc 'packed-switch' apktool_out/smali* \| sort -t: -k2 -rn \| head` |
| Exported components | `grep -n 'android:exported' apktool_out/AndroidManifest.xml` |
| Password fields | `grep -rl 'textPassword\|numberPassword' apktool_out/res/layout/` |
| Cloud keys | `grep -rEn 'AIza[0-9A-Za-z_-]{35}\|AKIA[0-9A-Z]{16}' out apktool_out` |

## Native `.so` recon

```bash
readelf --dyn-syms lib.so | grep -E 'Java_|JNI_OnLoad'
readelf -d lib.so | grep NEEDED
readelf -x .init_array lib.so
strings -n 8 lib.so | sort -u | head -100
nm -D --defined-only lib.so | head
```

| NEEDED entry | Implies |
|---|---|
| `liblog.so` | logs |
| `libz.so` | compress/inflate a blob |
| `libcrypto.so` / `libssl.so` | own TLS → native pinning |
| `libandroid.so` | asset access from native |
| `libdl.so` + few others | manual symbol resolution |

## Frida — attach modes

| Command | Runs at |
|---|---|
| `frida -U -n com.app` | after full start (too late for packers) |
| `frida -U -f com.app --pause` then `%resume` | before first instruction |
| `frida -U -f com.app -l s.js --pause` | script loaded before resume |
| `frida-trace -U -f com.app -j '*!*'` | all Java methods |
| `frida-trace -U -f com.app -i 'Java_*'` | all JNI exports |

## Frida one-liners

```javascript
// find the string decryptor: who builds Strings from bytes?
Java.perform(function(){var S=Java.use("java.lang.String"),E=Java.use("java.lang.Exception");
 S.$init.overload("[B").implementation=function(b){this.$init(b);
 var t=E.$new().getStackTrace(); if(t.length>1)console.log(t[1]+" => "+this.toString());};});

// exhaust an index-based decryptor
Java.perform(function(){var C=Java.use("com.x.q");
 for(var i=0;i<1024;i++){try{var v=C.a(i);if(v)console.log(i+" "+v);}catch(e){}}});

// list every ClassLoader (did unpacking happen?)
Java.perform(function(){Java.enumerateClassLoaders({onMatch:function(l){console.log(l);},onComplete:function(){}});});

// log class resolution
Java.perform(function(){var B=Java.use("dalvik.system.BaseDexClassLoader");
 B.findClass.implementation=function(n){console.log("[cls] "+n);return this.findClass(n);};});

// hook every ClassLoader constructor
Java.perform(function(){["dalvik.system.DexClassLoader","dalvik.system.PathClassLoader",
 "dalvik.system.InMemoryDexClassLoader"].forEach(function(n){var C=Java.use(n);
 C.$init.overloads.forEach(function(o){o.implementation=function(){
  console.log("[loader] "+n);return o.apply(this,arguments);};});});});

// log reflection
Java.perform(function(){var C=Java.use("java.lang.Class");
 C.forName.overload("java.lang.String").implementation=function(n){console.log("[forName] "+n);return this.forName(n);};});

// neutralise libc ptrace anti-debug
var p=Module.findExportByName(null,"ptrace");
if(p)Interceptor.replace(p,new NativeCallback(function(){return 0;},'long',['int','int','pointer','pointer']));

// discover libart DEX entry points on THIS device
Process.getModuleByName("libart.so").enumerateExports()
 .filter(function(e){return /DexFile/.test(e.name)&&/Open/.test(e.name);})
 .forEach(function(e){console.log(e.address+"  "+e.name);});

// carve DEX from memory
Process.enumerateRanges('r--').forEach(function(r){
 Memory.scanSync(r.base,r.size,'64 65 78 0a').forEach(function(m){try{
  var h=m.address,sz=h.add(32).readU32();
  if(h.add(36).readU32()!==0x70||h.add(40).readU32()!==0x12345678)return;
  if(sz<0x70||sz>0x20000000)return;
  var f=new File("/data/local/tmp/d_"+h+".dex","wb");f.write(h.readByteArray(sz));f.close();
  console.log("dumped "+sz+" @ "+h);}catch(e){}});});
```

## Objection

```
objection -g com.target.app explore
android hooking list classes
android hooking search classes crypt
android hooking watch class com.example.a.q
android hooking watch class_method com.example.a.q.a --dump-args --dump-return --dump-backtrace
android heap search instances com.example.a.q
memory list modules
memory dump all /tmp/memdump
```

## Technique → recognition → counter

| Technique | Recognise by | Counter |
|---|---|---|
| Renaming | `a`, `b`, `p001x` packages | semantic renaming from survivors |
| XOR strings | `xor-int/lit8` loop returning String | hook or call the decryptor |
| AES strings | `Cipher.getInstance` in a String helper | same — call it |
| Per-class decryptors | hundreds of tiny String helpers | hook `String.<init>([B)` |
| Opaque predicates | `x*x>=0`, `(x\|1)!=0` | execute and observe |
| Flattening | `while(true){switch(s)}` | state-transition table |
| Junk code | unread locals, discarded allocs | decompiler DCE |
| Irreducible loops | jadx "can't fix method" | read Smali |
| Reflection | `forName`/`getMethod`/`invoke` cluster | hook reflection API |
| Dynamic loading | `*ClassLoader` ctor + asset read | hook ctor, dump bytes |
| Native migration | logic behind `Java_*` exports | frida-trace the JNI boundary |
| Packer | `class_defs_size` tiny + blob + stub App | memory-dump the DEX |
| Anti-decompiler | tools fail, app installs | Smali, or dump from memory |
| Resource mangling | `res/layout/a.xml` | manifest + `aapt2 dump` |

## What survives obfuscation

Framework class/method names · string constants · manifest component names, permissions, exported
flags · resource names in `resources.arsc` · JNI symbol names in `.dynsym` · reflection target strings
· enum constant names (if `valueOf` used) · `Parcelable.CREATOR` · `Serializable` field names ·
runtime-retained annotations (Retrofit, Gson, Room) · `kotlin.Metadata` · class hierarchy and method
signatures · anything with a `-keep` rule.

## Deobfuscation methodology (order matters)

```
0 acquire + hash + all splits
1 triage: packed? renamed? strings? native? flattened? anti-analysis?
2 static or dynamic (prefer dynamic)
3 unpack if packed
4 STRINGS FIRST — find decryptor, exhaust it, annotate smali
5 control flow — only for methods the strings flagged
6 semantic renaming from evidence
7 write the model down
```

## Packer runtime order

```
zygote fork → ActivityThread.handleBindApplication → LoadedApk.makeApplication
→ StubApplication.attachBaseContext → System.loadLibrary
→ .init_array (ANTI-DEBUG RUNS HERE) → JNI_OnLoad (decrypt)
→ new *ClassLoader(realDex) → reflectively set LoadedApk.mClassLoader
→ real Application.onCreate
```

Hook before `System.loadLibrary` or you are too late.

## Version matrix

| Capability | 21–25 | 26–27 | 28–29 | 30+ |
|---|---|---|---|---|
| `InMemoryDexClassLoader` | no | yes | yes | yes |
| Hidden-API enforcement | no | no | yes (28) | yes, stricter |
| DEX from app-writable path | yes | yes | blocked (29, target 29+) | blocked |
| DEX version in the wild | 035/037 | 038 | 039 | 039–041 |
