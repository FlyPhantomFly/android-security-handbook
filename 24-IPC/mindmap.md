# 24 — IPC Mind Map

```mermaid
mindmap
  root((Android IPC))
    1 Why it exists
      Sandbox is absolute
        One app one UID
        No shared memory by default
        SELinux on top of DAC
      Framework is remote
        system_server owns the state
        Every manager is a proxy
        Permissions checked on the far side
      Without IPC
        No share sheet
        No SurfaceFlinger
        No permission model
    2 Two shapes
      Mediated by system_server
        Policy enforceable
        Visible in the manifest
        dumpsys can show it
      Direct app to app
        No framework involvement
        Invisible to manifest tools
        Only DAC SELinux and app code
    3 Mediated mechanisms
      Intents
        Explicit vs implicit
        Action data type category
        Extras are hostile input
        Deep links
        App Links and assetlinks.json
        Custom scheme hijack
      Bound services
        AIDL Stub and Proxy
        Transaction codes
        Messenger and Handler
        replyTo is attacker chosen
      ContentProviders
        query insert update delete
        call and openFile
        URI grants
        SQL injection points
        Path traversal
      Broadcasts
        Receiving side
        Sending side leaks
        Ordered and priority
        Sticky deprecated
        Protected broadcasts
    4 Direct mechanisms
      UNIX domain sockets
        Filesystem named
          DAC and SELinux apply
        ABSTRACT namespace
          Leading NUL byte
          No inode no permissions
          Every app can connect
          LocalServerSocket default
          chrome_devtools_remote
        SO_PEERCRED
      Localhost sockets
        INTERNET is auto granted
        127.0.0.1 vs 0.0.0.0
        Debug servers left in release
        DNS rebinding from a browser
      Shared files
        External storage
        MODE_WORLD_READABLE history
        setReadable true false
        FileProvider is the fix
      Shared memory
        ashmem and MemoryFile
        memfd and sealing
        CursorWindow uses it
        TOCTOU on shared bytes
      Clipboard
        Global buffer
        Foreground only since API 29
        EXTRA_IS_SENSITIVE API 33
      Settings Secure and Global
        Read by almost anyone
        Untrusted input not a channel
      File descriptors over Binder
        ParcelFileDescriptor
        openFile traversal
        Attacker chosen destination
    5 Identity
      getCallingUid
        Kernel supplied
        Cannot be forged
        Authorise on this
      getCallingPid
        Truthful at the instant
        PIDs are recycled
        Log only never decide
      clearCallingIdentity
        Check before clear
        Narrow the window
        Restore in finally
        Strict LIFO
      Signature over package name
    6 Confused deputy
      Hardy 1988
      Deputy has authority
      Request names a target
      No check on entitlement
      Android forms
        Intent redirection
        URI grant theft
        Permission re delegation
        Mutable PendingIntent
    7 Methodology
      Step 0 record targetSdk
      Step 1 manifest inventory
      Step 2 code level channels
      Step 3 live enumeration
      Step 4 prove from a real app
      Step 5 reach through analysis
      Step 6 exploit and evidence
      Step 7 honest severity
    8 Tooling
      adb
        dumpsys package
        am and content
        proc net unix and tcp
      Drozer
        attacksurface
        provider scanners
        service send
      Frida
        trace ipc js
        onTransact hook
        getCallingUid hook
      Static
        jadx and apktool
        grep corpus
        native strings and nm
    9 Honest reporting
      Shell is not an app
      Walk the reach through
      State targetSdk and build
      Record what you ruled out
```
