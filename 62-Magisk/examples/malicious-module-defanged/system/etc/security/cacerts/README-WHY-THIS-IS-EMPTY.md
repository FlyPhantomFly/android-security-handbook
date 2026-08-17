# LAB FIXTURE — this directory is deliberately empty

A trojanised module would ship a real CA certificate here, named with the correct
`-subject_hash_old` value plus a `.0` suffix, so that Android's trust store picks it up.

This fixture ships **no certificate**, for the obvious reason: a real CA in a public repository is a
real CA that anyone can use, and the fixture is meant to be read rather than run.

What matters for [Lab 04](../../../../../../labs/lab-04-module-audit.md) is that the *directory exists*
inside the module's `system/` tree. That alone is the finding, and it is visible from `unzip -l`
without reading a single script:

```
system/etc/security/cacerts/
```

A module that installs a CA into the system trust store makes every TLS connection on the device
interceptable by whoever holds the matching private key — including the connections of applications
that have nothing to do with the module. There is exactly one legitimate reason to do this, which is
an authorised test device you control, and in that case you know you asked for it.
