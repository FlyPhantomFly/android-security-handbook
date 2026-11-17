# 62 — Magisk · Examples

Three complete Magisk modules, shipped as **sources**. None of them is a built `.zip`, and none ever
will be: this repository does not commit build artefacts, and a module ZIP is one. Every directory
here contains the command that produces its archive, which is one line.

---

## How a module becomes a ZIP

Magisk looks for `module.prop` at the **root** of the archive. The single most common packaging
mistake is producing an archive whose entries all begin with the directory name.

```bash
# host — correct: cd in, zip the contents
cd system-ca-module && zip -r ../systemca.zip . -x '.*' -x '__MACOSX/*' && cd ..

# verify before you push anything to a device
unzip -l systemca.zip | head -20        # module.prop must appear with no directory prefix
```

```bash
# host — WRONG. Produces entries named "system-ca-module/module.prop".
zip -r systemca.zip system-ca-module/
```

Build into a scratch directory outside this repository. The `.zip` files are on the artefact
blocklist and must never be committed.

---

## What is here

| Directory | What it demonstrates | Used by |
|---|---|---|
| [`system-ca-module/`](system-ca-module/) | A `system/` overlay module: the bind-mount mechanism, correct trust-store filenames, `customize.sh` and permissions | [Lab 02](../labs/lab-02-write-a-module.md) Part 2, [Lab 03](../labs/lab-03-denylist-investigation.md) |
| [`pentest-prep-module/`](pentest-prep-module/) | A scripts-only module: `skip_mount`, boot stages, `system.prop`, `sepolicy.rule`, `uninstall.sh` | [Lab 02](../labs/lab-02-write-a-module.md) Part 3 |
| [`malicious-module-defanged/`](malicious-module-defanged/) | **A deliberately hostile module, defanged.** Every dangerous action is present as text and neutralised in execution | [Lab 04](../labs/lab-04-module-audit.md) |

> **Warning — `malicious-module-defanged/`**
> That directory contains a module written to be caught. Every hostile action it describes is real
> and is exactly what a trojanised module would do; every one of them is routed through a `would()`
> wrapper that prints the command instead of running it, and the module refuses to do anything at all
> unless a lab environment variable is set. It is a **teaching fixture for
> [Lab 04](../labs/lab-04-module-audit.md)**, not a payload. Read its own README before touching it,
> and do not install it on any device, defanged or not.

---

## A note on paths

The chapter's §9.2 shows the CA module as a tree:

```
systemca/
├── module.prop
├── customize.sh
└── system/etc/security/cacerts/9a5ba580.0
```

The shipped copy matches that tree exactly, except that the certificate itself is absent — a
certificate is device- and proxy-specific, and shipping one would be shipping a private CA nobody
should trust. `system/etc/security/cacerts/` therefore holds only a placeholder, and
`system-ca-module/README.md` tells you how to produce the real file with the right name.

---

## Auditing any of these

The chapter's audit script reads a module archive and reports what it will execute and when. Run it
against all three, including the two benign ones, so you know what a clean report looks like before
you try to read a dirty one:

```bash
# host
cd system-ca-module && zip -qr /tmp/ca.zip . -x '.*' && cd ..
../scripts/audit-magisk-module.sh /tmp/ca.zip
```

See [`../scripts/audit-magisk-module.sh`](../scripts/audit-magisk-module.sh).
