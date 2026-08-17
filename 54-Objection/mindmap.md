# 54 — Objection mind map

One map of the whole chapter. Measured against objection 1.11.0 / frida 16.1.6 on a rooted
Redmi `M2101K6P`, Android 11 / API 30.

```mermaid
mindmap
  root((54 Objection))
    1 What it IS
      A pre-written Frida agent plus a REPL
        Not a capability, an ergonomics layer
        Every command is a canned script
        53-Frida owns the runtime
      agent.js
        1045437 bytes measured
        125 browserify modules
        Loaded WHOLE at connect
        Includes iOS code on Android targets
        7.6 MB QuickJS heap in the target
      Python side is nearly empty
        pinning.py 26 lines
        root.py 25 lines
        All intelligence in agent.js
    2 Why it fails
      Because it is Frida
        No root and no gadget
        Version skew
        SELinux, wrong ABI
      Because it is PRE-written
        Implementation the author never saw
      Because it is a FIXED LIST
        The check is not on the list
      Because it loads when you connect
        The code already ran
      Because it targets a Frida API
        That API changed
    3 android root disable
      EXACTLY three hooks
        String.contains "test-keys"
        Runtime.exec String endsWith su
        File.exists on 13 exact paths
      Does NOT cover
        Any path off the list
        exec String array overload
        ProcessBuilder
        PackageManager queries
        proc mounts and maps
        SELinux state
        Settings.Global
        RootBeer native
        ANYTHING native
        Play Integrity
      Measured
        1 of 5 checks influenced
        A bug: this.apply returns non-Process
        A hook that installed and never fired
    4 android sslpinning disable
      Seven hooks
        SSLContext.init
        okhttp3 CertificatePinner check
        check$okhttp hardcodes u15
        Appcelerator PinningTrustManager
        TrustManagerImpl verifyChain
        TrustManagerImpl checkTrustedRecursive
        PhoneGap SSLCertificateChecker
      Three always install
        They are PLATFORM classes
        Measured on an app with NO network
      Not covered
        Native BoringSSL Flutter Cronet
        network_security_config pin-set
        WebView is INERT
        TrustKit, CT, Volley, Xamarin
      Found means class exists
      Called means the path ran
      quiet hides the useful half
    5 The command surface
      explore run api patchapk signapk
      env frida ping jobs
      android hooking
        list classes 16087 measured
        search classes by package
        list class_methods = SIGNATURES
        watch class_method dump flags
        set return_value boolean only
        generate simple = your scaffold
      heap search instances
      keystore list watch clear
      memory list modules 309 measured
      sqlite connect misses the WAL
      file ls cat download upload http
      intent launch_activity
    6 Attach or spawn
      Attach if running
      Spawn if not
      Chosen SILENTLY
      No flag to force it
      am force-stop first, always
      Same command, opposite results
    7 Version skew
      objection to frida via pip
      frida to frida-server MAJOR must match
      agent.js to server JS API
        Nothing checks this
        Connects then fails per command
      Agent injected ok proves the WIRE
      Pin all three
      Ignore the upgrade banner
      scripts objection-doctor.py
    8 Four failure modes
      1 Injection never happened
      2 Class not in the process
      3 Hook landed too late
      4 Outside the canned envelope
      3 and 4 look identical
        force-stop separates them
    9 Honest severity
      Bypass is an observation
      Pinning is a control not a vulnerability
      36 rejects the bounty framing
      No arrow OBSERVE to REPORT
      Escalation is server-side
      Never paste output into findings
    10 The trade
      Speed bought with knowledge
      Right for is anything here
      Wrong for why did that happen
      Save time never understand
      Exit when you need WHY
      Read your own agent.js
```

---

## The one-paragraph version

Objection is a megabyte of pre-written Frida agent with a prompt in front of it. It is the
correct first move on an unfamiliar app, because reconnaissance is where you least want to be
writing code. It becomes the wrong tool the instant your question turns from *"is there
anything here?"* into *"why did that happen?"* — because its commands are designed to produce
an effect, and they cannot tell you which of their hooks produced it. `android root disable` is
three hooks and thirteen hard-coded paths; `android sslpinning disable` is seven hooks, three
of which install against every Android application ever written. Read your own `agent.js`
before you trust either.

## Related maps

- [53-Frida mindmap](../53-Frida/mindmap.md) — the runtime underneath
- [51-DynamicAnalysis mindmap](../51-DynamicAnalysis/mindmap.md) — the method this serves
- [37-RootDetection mindmap](../37-RootDetection/mindmap.md) — the taxonomy §3.5 maps onto
- [36-CertificatePinning mindmap](../36-CertificatePinning/mindmap.md) — the seven pinning layers
