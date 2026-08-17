# Lab 01 — Build Your Lab

> **Difficulty:** Beginner · **Time:** 90–180 minutes · **Chapter:** [00 — Introduction](../README.md)

Every other lab in this repository assumes the machine you are sitting at can talk to an Android
device, decompile an APK, and inject code into a running process. This lab builds that machine. It
is deliberately the longest setup document you will read here, because a broken toolchain is the
single most common reason people abandon Android security in their first month. They conclude they
are not smart enough, when in fact `JAVA_HOME` was pointing at a JRE.

---

## Objective

By the end of this lab you will have a workstation on which all seven of the following commands
print a version number rather than an error, and you will understand what each tool actually does
rather than merely that it is "needed".

| Tool | One-line purpose | Verification command |
|---|---|---|
| JDK (Java Development Kit) | Runs the Java-based tools; `jadx` and `apktool` are Java programs | `java -version` |
| Android SDK platform-tools | Provides `adb` and `fastboot`, the only official channel to a device | `adb version` |
| Python 3 + virtualenv | Hosts Frida, Objection, MobSF and every script you will write | `python3 --version` |
| Frida | Injects a JavaScript engine into a live process so you can change its behaviour | `frida --version` |
| jadx | Turns compiled DEX bytecode back into readable Java | `jadx --version` |
| apktool | Unpacks and repacks an APK, decoding binary XML and resources | `apktool --version` |
| unzip | An APK is a ZIP file; you will open it as one constantly | `unzip -v` |

> **📖 Definition — toolchain.** A *toolchain* is the ordered set of programs that transform an
> artefact from one representation into another. In Android security the chain runs from the signed
> APK on disk, through unpacking, through decompilation, to a readable representation, and then
> back the other way when you patch and repack. Each tool in the chain assumes the previous one
> succeeded, which is why a single broken link produces errors that look unrelated to the real cause.

> **🧠 Mental Model.** Think of the toolchain as a mechanic's bay rather than a single machine. The
> JDK is the electricity supply — nothing Java-based runs without it. `adb` is the ramp that gets
> the vehicle into the bay. `jadx` and `apktool` are the ways you take the engine apart. Frida is
> the diagnostic probe you clip onto the engine *while it is running*. You would not judge a
> mechanic by owning tools, and nobody will judge you by having installed these; the tools are the
> precondition for the work, not the work.

---

## Prerequisites

- A computer running Windows 10/11, macOS 12+, or a mainstream Linux distribution.
- Administrator or `sudo` rights on that computer. Several steps write to system paths.
- At least 20 GB of free disk space. An Android emulator system image alone is 8–12 GB.
- An internet connection that is not behind a proxy that rewrites TLS, or, if it is, the patience to
  add corporate CA certificates to the JDK truststore.
- No prior Android or programming knowledge. If you do not know what a "shell" is, read
  [02 — Linux Basics](../../02-Linux-Basics/README.md) first; this lab will still work, but you
  will be typing rather than understanding.

> **⚠️ Warning.** Do not install these tools on a machine you need to keep pristine for other work,
> and never on a machine that holds client data for an unrelated engagement. Analysis workstations
> routinely execute untrusted code — that is their entire purpose. A dedicated laptop or a virtual
> machine you can snapshot and roll back is the professional norm.

---

## Setup

### Choose your platform line

Every step gives one command per operating system in a single block. Run only the line that matches
your machine. On Windows, "PowerShell" means the terminal you get from Start → *Windows PowerShell*;
"elevated PowerShell" means right-click it and choose *Run as administrator*.

### Install a package manager first (Windows and macOS)

A package manager installs software and its dependencies from a curated index, so you do not hunt
for installers. Linux already has one (`apt`, `dnf`, `pacman`). Windows 10/11 ships `winget`, which
is sufficient on its own, though some tools below are only packaged for Chocolatey.

```bash
# host — pick your platform
# Windows, elevated PowerShell — installs Chocolatey alongside the built-in winget:
#   Set-ExecutionPolicy Bypass -Scope Process -Force
#   iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
# macOS — installs Homebrew:
#   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
# Debian/Ubuntu — just refresh the index:
sudo apt update
```

> **🔬 Under the Hood.** A package manager is a database plus an unpacker. It records which files
> belong to which package and which packages depend on which others, so removal is exact and
> upgrades do not leave orphans. When you later install `frida-server` on a device by hand, you are
> doing manually what a package manager would otherwise do for you, which is exactly why it is easy
> to end up with three stale copies in `/data/local/tmp`.

---

## Steps

### Step 1 — Install the JDK

`jadx`, `apktool`, and the Android build tools are Java programs. They need a **JDK** (Java
Development Kit), not merely a **JRE** (Java Runtime Environment). The JRE can run Java programs;
the JDK can also compile them and ships the diagnostic tools (`javap`, `jps`, `jstack`) you will
want in [04 — Java](../../04-Java/README.md).

```bash
# host — install, then verify. Run only the line for your platform.
# Windows : winget install --id EclipseAdoptium.Temurin.21.JDK -e
# macOS   : brew install --cask temurin@21
# Linux   : sudo apt install -y openjdk-21-jdk

java -version      # all platforms — note this prints to stderr, not stdout
javac -version
```

You should see a version line naming a build of Java 17 or newer. If `javac` is missing but `java`
works, you installed a JRE.

> **⚠️ Warning — JAVA_HOME.** Many Java tools read the `JAVA_HOME` environment variable instead of
> searching your `PATH`. If it is unset, or points at an old JDK you deleted, `apktool` will fail
> with messages that mention neither Java nor `JAVA_HOME`.

```bash
# host — set JAVA_HOME permanently
# Windows, PowerShell:
#   [Environment]::SetEnvironmentVariable('JAVA_HOME','C:\Program Files\Eclipse Adoptium\jdk-21','User')
# macOS/Linux — append to ~/.zshrc or ~/.bashrc:
export JAVA_HOME="$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")"
export PATH="$JAVA_HOME/bin:$PATH"
```

Open a **new** terminal after changing environment variables. An already-running shell keeps the
environment it was started with; this single fact accounts for a large share of "I set it and it
still doesn't work" reports.

### Step 2 — Install Android SDK platform-tools

`platform-tools` is the small archive containing `adb` (Android Debug Bridge) and `fastboot`. You do
not need the whole Android Studio installation to do security work, though you will want it later
for the emulator and for building test apps.

> **📖 Definition — adb.** The *Android Debug Bridge* is a three-part system: a client (`adb` on
> your host), a server (a background process on your host that owns the USB and TCP connections),
> and a daemon (`adbd`) running on the device. Commands you type reach `adbd` over USB or TCP, and
> `adbd` executes them with whatever privileges it holds. The protocol itself is dissected in
> [60 — ADB](../../60-ADB/README.md).

```bash
# host — install, then verify
# Windows : winget install --id Google.PlatformTools -e     (or: choco install adb -y)
# macOS   : brew install --cask android-platform-tools
# Linux   : sudo apt install -y android-sdk-platform-tools

adb version
adb start-server
```

If your distribution's package is old, download the official ZIP from the Android developer site,
unzip it to a directory of your choice, and add that directory to `PATH`. Distribution packages of
`platform-tools` lag upstream by months, and an `adb` older than the device's Android version can
fail to see the device at all.

### Step 3 — Create a Python environment

Python hosts Frida, Objection, and most of your own tooling. Install Python 3.10 or newer, then
create a **virtual environment**.

> **📖 Definition — virtual environment.** A *virtualenv* is a directory containing its own copy of
> the Python interpreter's script entry points and its own `site-packages` folder. Activating it
> prepends that directory to `PATH`, so `pip install` writes there instead of into the system
> Python. This matters because Frida is version-sensitive: the `frida` Python package and the
> `frida-server` binary on the device must match, and you will eventually need two different
> versions for two different targets. Separate virtualenvs make that painless instead of painful.

```bash
# host — install Python, create the environment, activate it
# Windows : winget install --id Python.Python.3.12 -e
#           python -m venv "$HOME\androidsec"
#           & "$HOME\androidsec\Scripts\Activate.ps1"
# macOS   : brew install python@3.12
# Linux   : sudo apt install -y python3 python3-pip python3-venv

# macOS and Linux:
python3 -m venv ~/androidsec
source ~/androidsec/bin/activate
```

Your prompt should now be prefixed with `(androidsec)`. That prefix is the only reliable indication
that the environment is active. Every Frida command in this repository assumes it is.

### Step 4 — Install Frida and Objection

```bash
# host — inside the activated virtualenv, all platforms
pip install --upgrade pip
pip install frida-tools objection
frida --version
objection version
```

Frida installs two halves. The half you just installed is the **client**: the `frida`, `frida-ps`,
and `frida-trace` commands that run on your host. The other half is `frida-server`, an ELF binary
that must run **on the device**, usually as root, and whose version must match the client exactly.
You will place it there in [Lab 02](lab-02-first-60-minutes.md)'s follow-on chapters; the mechanics
belong to [53 — Frida](../../53-Frida/README.md).

> **🔍 Pentester's Note.** Record the exact Frida version in your engagement notes on day one. When
> a client asks six months later why a finding no longer reproduces, "Frida 16.x against Android 14"
> is the difference between a credible answer and a shrug. Tool versions are evidence.

### Step 5 — Install jadx

`jadx` reads the DEX bytecode inside an APK and reconstructs Java source. The reconstruction is a
best-effort decompilation, not the original source: names may be lost to obfuscation, and some
constructs will not decompile at all. Its internals and failure modes are covered in
[56 — JADX](../../56-JADX/README.md).

```bash
# host — install, then verify
# Windows : choco install jadx -y
# macOS   : brew install jadx
# Linux   : the distro package is often stale — download the official release ZIP,
#           then:  unzip jadx-*.zip -d ~/tools/jadx
#           and add ~/tools/jadx/bin to PATH in your shell rc file

jadx --version
```

### Step 6 — Install apktool

`apktool` does something different from `jadx` and the two are not interchangeable. `jadx` produces
*readable Java you cannot rebuild*. `apktool` produces *Smali and decoded resources you can rebuild
into a working APK*. When your goal is understanding, reach for `jadx`. When your goal is patching,
reach for `apktool`.

```bash
# host — install, then verify
# Windows : choco install apktool -y
# macOS   : brew install apktool
# Linux   : sudo apt install -y apktool

apktool --version
```

### Step 7 — Confirm `unzip` exists

An APK is a ZIP archive with a fixed internal layout. You will open one by hand in
[Lab 02](lab-02-first-60-minutes.md).

```bash
# host — macOS already ships unzip
# Windows : choco install unzip -y   (PowerShell's built-in Expand-Archive also works)
# Linux   : sudo apt install -y unzip
unzip -v
```

### Step 8 — Run the verification script

This repository ships a script that performs every check above in one pass.

```bash
# host — from the repository root
sh 00-Introduction/scripts/verify-toolchain.sh
```

On Windows, run it from Git Bash or WSL. The script exits non-zero if a critical tool is missing, so
you can use it as a pre-flight check inside your own automation later.

---

## Hints

- If a command "is not recognised" immediately after installing it, the cause is almost always that
  the shell was open before the installer edited `PATH`. Close every terminal and open a new one.
- On Windows, `where.exe adb` and on macOS/Linux `command -v adb` tell you which copy of a tool is
  actually being run. If you have two, the first one on `PATH` wins, and it may not be the one you
  just installed.
- `pip install frida` inside a virtualenv that is not activated silently installs into the system
  Python. Check `python -c "import sys; print(sys.prefix)"` — it should print your virtualenv path.
- Antivirus software on Windows regularly quarantines `frida-server` and `adb` because their
  behaviour is indistinguishable from malware by design. Add an exclusion for your tools directory
  rather than disabling protection wholesale.
- Corporate TLS interception breaks `pip` and `brew`. The symptom is a certificate verification
  error, not a network error. The fix is to add the corporate root CA to the relevant truststore,
  never to pass `--trusted-host` blindly.

---

## Solution

A completed workstation produces output resembling the following. Exact version numbers will differ
and that is expected; what matters is that each command returns rather than errors.

```text
# host — expected shape of output, versions will vary
$ java -version
openjdk version "21.0.4" 2024-07-16 LTS

$ adb version
Android Debug Bridge version 1.0.41

$ python3 --version
Python 3.12.3

$ frida --version
16.x.x

$ jadx --version
1.5.x

$ apktool --version
2.x.x

$ unzip -v | head -1
UnZip 6.00 of 20 April 2009
```

### Verification checklist

Tick every row before you move on. A partially built lab wastes more time than an unbuilt one,
because you will misattribute failures to the target app.

| # | Check | Command | Expected result | Done |
|---|---|---|---|---|
| 1 | JDK present, not just JRE | `javac -version` | A version line, Java 17+ | ☐ |
| 2 | `JAVA_HOME` set and correct | `echo $JAVA_HOME` / `$env:JAVA_HOME` | A path that contains `bin/javac` | ☐ |
| 3 | `adb` on PATH | `adb version` | Version 1.0.41 or newer | ☐ |
| 4 | adb server starts | `adb start-server` | `daemon started successfully` or silence | ☐ |
| 5 | Python 3.10+ | `python3 --version` | 3.10 or newer | ☐ |
| 6 | Virtualenv active | prompt shows `(androidsec)` | Prefix visible | ☐ |
| 7 | Frida client | `frida --version` | A 16.x or newer version | ☐ |
| 8 | Objection | `objection version` | A version line | ☐ |
| 9 | jadx | `jadx --version` | A version line | ☐ |
| 10 | apktool | `apktool --version` | A version line | ☐ |
| 11 | unzip | `unzip -v` | Banner line | ☐ |
| 12 | Repo script passes | `sh scripts/verify-toolchain.sh` | Exit code 0 | ☐ |

### Troubleshooting table

These are real messages you will see, with the real cause rather than the obvious one.

| Error message | What it actually means | Fix |
|---|---|---|
| `adb: command not found` / `'adb' is not recognized` | `platform-tools` is installed but its directory is not on `PATH`, or the shell predates the change | Add the directory to `PATH`, then open a new terminal |
| `adb server version (41) doesn't match this client (39); killing...` | Two different `adb` binaries are on the machine; another program (Android Studio, a vendor tool) started an older server | `adb kill-server`, remove the older binary or fix `PATH` order, then `adb start-server` |
| `error: no devices/emulators found` | The device is connected but USB debugging is off, the authorisation prompt was never accepted, or the cable is charge-only | Enable USB debugging, accept the RSA prompt on the device, and try a known-good data cable |
| `error: device unauthorized` | The device has not trusted this host's ADB RSA key | Unlock the device, accept the "Allow USB debugging?" dialog, tick "Always allow" |
| `INSTALL_FAILED_NO_MATCHING_ABIS` | The APK contains native libraries for CPU architectures the target does not have — typically an arm64-only APK being pushed to an x86 emulator | Use an arm64 device, or create an emulator with an `arm64-v8a` image, or install a build that includes the right ABI |
| `INSTALL_FAILED_UPDATE_INCOMPATIBLE` | A package with the same name is already installed and was signed with a different key | `adb uninstall <package>` first, accepting that its data is destroyed |
| `Failed to connect to frida-server` / `unable to connect to remote frida-server` | `frida-server` is not running on the device, is listening on a different port, or was killed by the system | Push and start `frida-server` as root, confirm with `adb shell ps -A \| grep frida` |
| `Unable to communicate with remote frida-server; please ensure that major versions match` | Client and server versions differ | Install the exact matching `frida-server` release for your client version |
| `JAVA_HOME is not set and no 'java' command could be found` | Environment variable missing or stale | Set `JAVA_HOME` to the JDK root — the directory containing `bin/`, not `bin/` itself |
| `Error: LinkageError occurred while loading main class brut.apktool.Main` | The JDK is too old for the installed `apktool` | Install a newer JDK, or an `apktool` release matching your JDK |
| `Exception in thread "main" java.lang.OutOfMemoryError: Java heap space` (jadx) | The APK is large and the JVM's default heap is too small | Run `jadx -j 1 --show-bad-code` on a smaller scope, or raise the heap via the `JAVA_OPTS`/`JADX_OPTS` mechanism your build supports |
| `pip: SSL: CERTIFICATE_VERIFY_FAILED` | A TLS-intercepting proxy is between you and PyPI | Install the proxy's root CA into the system store and into `certifi` |
| `zsh: permission denied: ./frida-server` | The pushed binary has no execute bit, or is on a `noexec` mount | `chmod 755` it, and place it under `/data/local/tmp` |

---

## Success Criteria

You have completed this lab when all of the following are true:

1. Every row of the verification checklist is ticked in a **freshly opened** terminal — not the one
   you did the installation in.
2. `sh 00-Introduction/scripts/verify-toolchain.sh` exits with code `0`. Check with `echo $?`
   immediately after running it.
3. You can state, in one sentence each and without looking, what `adb`, `jadx`, `apktool`, and
   Frida do, and how `jadx` differs from `apktool`.
4. You have written down your tool versions somewhere durable. A file called `TOOLCHAIN.md` in your
   notes directory is enough.

---

## Going Further

- **Pin your versions.** Record the exact versions in a `requirements.txt` for the Python side and a
  plain list for everything else. Reproducibility is what separates a finding from an anecdote.
- **Snapshot the machine.** If you are working in a VM, take a snapshot now and label it
  "clean toolchain". You will corrupt this environment eventually; getting back should take minutes.
- **Install the rest of the stack.** Burp Suite Community, MobSF, and Ghidra are covered in
  [55 — MobSF](../../55-MobSF/README.md) and [57 — Ghidra](../../57-Ghidra/README.md). They are not
  required for Labs 02 and 03.
- **Add a second Python environment** with a deliberately older Frida, named `androidsec-frida15`.
  Real targets sometimes only cooperate with a specific version, and having the alternative already
  built saves an hour under time pressure.
- **Read [02 — Linux Basics](../../02-Linux-Basics/README.md)** if any part of `PATH`, environment
  variables, or file permissions felt like incantation rather than mechanism. Everything in this lab
  has a concrete explanation and none of it is magic.

---

**Next:** [Lab 02 — Your First 60 Minutes](lab-02-first-60-minutes.md) — connect a device, pull a
real APK, and take it apart by hand.
