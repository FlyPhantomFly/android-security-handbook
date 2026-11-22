# 81 — Android Runtime Internals · Mind Map

One picture of the whole chapter. Read it outward from the centre: an app is a specialized zygote
child; ART decides per method how to execute it; `ArtMethod` is where that decision is stored; and
every runtime tool in this chapter — Zygisk, ZygiskNext, Vector, LSPlant — occupies a different layer
of the path from the fork to the hooked call. Every branch corresponds to a section of
[the chapter README](README.md); use it as a revision map before an engagement or an interview.

```mermaid
mindmap
  root((Android Runtime<br/>Internals))
    Why it exists
      App is a process not a file
      Decisions happen in memory
      Static analysis cannot see state
      Hooking is dual use
    Process creation
      init
        init.zygote64.rc
        app_process64
      ZygoteInit
        create socket
        preload classes
        preload resources
        start system_server
        accept loop
      fork
        copy-on-write
        shared boot image
        shared JIT cache
      specialization
        UID and GID
        supplementary groups
        capabilities
        process name
        no_new_privs
        seccomp
        SELinux context
        mount namespace
      USAP
      child zygotes
    ART startup
      AndroidRuntime::start
      Runtime::Init
      heap
      thread list
      class linker
      JIT
      instrumentation
      boot image
      boot class path
    Execution pipeline
      interpreter
        switch
        nterp
        eligibility
      JIT
        hotness counter
        code cache
        OSR
        profile
      AOT
        dex2oat
        OAT
        VDEX
        speed-profile
        ART Service
      JNI
      deoptimization
    ArtMethod
      declaring_class_
      access_flags_
      dex_method_index_
      method_index_
      hotness_count_ or imt_index_
      data_
      entry_point_from_quick_compiled_code_
      version matrix
      no stable ABI
    Entrypoints
      AOT code
      JIT code
      nterp
      resolution stub
      class-init stub
      JNI trampoline
      deopt bridge
      quick is a convention
    Dispatch
      direct
      virtual vtable
      interface IMT
      JNI
      inlining
      devirtualization
      OSR
    Class loading
      boot class path
      PathClassLoader
      DexClassLoader
      InMemoryDexClassLoader
      parent delegation
      DexPathList
      defining loader
      class identity
    Hidden API
      member flags
      caller domain
      target SDK
      exemptions
      trusted DEX
      MakeDexFileTrusted
      not SELinux
    Zygisk
      API v5
      onLoad
      preAppSpecialize
      postAppSpecialize
      preServerSpecialize
      postServerSpecialize
      connectCompanion
      setOption
      exemptFd
      DenyList
      module loaded after fork
    ZygiskNext
      standalone
      KernelSU
      Magisk
      APatch
      ptrace loader
      libzgn
      zygiskd
      companion sockets
      memfd delivery
      API v4 extension
      closed source since 4-0.9.2
      ABI support
    Vector
      renamed from LSPosed
      Zygisk module
      daemon
      manager
      scope
      system_server
      in-memory framework DEX
      IPC bridge
      dex2oat wrapper
      inline-max-code-units 0
      libxposed API 102
      hot reload
    LSPlant
      InitInfo
      inline hooker
      symbol resolver
      Hook
      backup method
      trampoline
      flags
      Unhook
      Deoptimize
      JIT integration
      inlined callers
    Detection
      maps
      memfd
      TracerPid
      SELinux context
      mount namespace
      class loaders
      entrypoints
      OAT header
      build-matched baseline
      server-side evidence
    Mistakes
      hard-coded offsets
      blaming the hook
      ignoring inlining
      disabling SELinux
      filename attribution
      closed-source claims
```
