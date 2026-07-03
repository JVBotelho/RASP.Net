# Security Policy

## 🛡️ Reporting Security Vulnerabilities

**RASP.Net is a security research project.** If you discover a vulnerability in the RASP itself (ironic, we know!), please report it responsibly.

### Where to Report

**DO NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **[security.mullets599@passinbox.com]** with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will respond within **48 hours** and provide a timeline for a fix.

---

## 🔒 Supported Versions

| Version | Supported          |
|:--------|:-------------------|
| 1.x     | ✅ Active development |
| < 1.0   | ❌ PoC/Pre-release    |

---

## 🎯 Known Limitations (By Design)

This is a **Proof of Concept** with inherent limitations:

### Intentional Scope Restrictions

1. **Taint Tracking is v1/Windows-only**: A native CLR profiler propagates a taint bit through
   `String.Concat(string, string)` only; other string-building patterns (interpolation,
   `StringBuilder`, `string.Format`) are not yet tracked, and the profiler is Windows-only.
   - **Impact**: Obfuscated/indirect data flow outside the tracked pattern may bypass taint-based
     detection
   - **Mitigation**: Defense-in-depth — detection also runs at the gRPC entrypoint and at each
     sink (SQL, XSS, SSRF, Path Traversal, Command Injection, Deserialization) independent of taint

2. **Signature/Heuristic-Based Detection**: Uses pattern and heuristic matching, not behavioral
   or ML-based analysis
   - **Impact**: Novel/zero-day attacks may not be detected
   - **Mitigation**: Regular pattern updates; sink-level ground-truth checks (e.g., path/executable
     allowlists) don't rely on pattern matching at all

3. **Performance Overhead**: Sink interception adds latency at each guarded call
   - **Impact**: Measured overhead is indistinguishable from noise against the real I/O being
     guarded (file open, process spawn, DB round trip, outbound HTTP) under sustained load — see
     [ADR 006](docs/ADR/006-sink-instrumentation-strategy.md#measured-end-to-end-latency-under-sustained-load-2026-07-02)
     for methodology and numbers
   - **Mitigation**: Benchmarking tools provided; audit mode (`BlockOnDetection = false`) available
     if inspection cost is a concern for a given deployment

4. **Deserialization guard is a type blocklist, wired to `System.Text.Json` only**: it checks
   deserialized types against a curated list of ~12 known gadget-chain types, and only
   `Rasp.Instrumentation.SystemTextJson`'s `JsonTypeInfo` modifier calls it — there's no hook for
   `BinaryFormatter`, Json.NET with `TypeNameHandling`, `DataContractSerializer`, or `LosFormatter`
   - **Impact**: A blocklist is bypassable by any gadget type not on the list (e.g. most of
     `ysoserial.net`'s catalog); the other serializers listed above have no coverage at all if used
   - **Mitigation**: Don't use `BinaryFormatter` (obsolete/removed in modern .NET) or
     `TypeNameHandling.All`-style polymorphic deserialization of untrusted input regardless of
     RASP; the architecturally correct fix — allowlist enforcement via a custom
     `SerializationBinder` — is listed in [ADR 006](docs/ADR/006-sink-instrumentation-strategy.md)
     Phase A but not yet implemented

### Attack Vectors NOT Currently Covered

- ❌ NoSQL Injection (MongoDB, Cosmos DB)
- ❌ LDAP Injection
- ❌ XML External Entity (XXE)
- ❌ Server-Side Template Injection (SSTI)

### Covered

SQL Injection, XSS, SSRF, Path Traversal, Command Injection, and Insecure Deserialization all
have dedicated sink-level guards; see [ROADMAP.md](docs/ROADMAP.md) for the current feature
matrix and per-sink status.

---

## 🔐 Security Best Practices for Users

If you're deploying RASP.Net in a test/production environment:

### 1. Defense in Depth
RASP is **not a replacement** for:
- Input validation at API boundaries
- Parameterized queries (use EF Core correctly!)
- Web Application Firewalls (WAF)
- Network segmentation

### 2. Don't swallow `RaspSecurityException`
Every guard blocks by throwing `Rasp.Core.Exceptions.RaspSecurityException` (deliberately not
derived from `DbException`, so EF Core doesn't treat a block as a transient fault and retry it).
That also means the block only takes effect if the exception is allowed to propagate: a broad
`catch (Exception)` around a query, file operation, or process call in application code will
silently swallow the block and let the request continue. This is an inherent property of any
throw-to-block RASP, not something RASP.Net can enforce from inside the process — treat "don't
catch `RaspSecurityException`" as a deployment requirement, the same way you'd treat "don't catch
`OperationCanceledException` and continue" for cancellation.

### 3. Logging and Monitoring
`AddRasp` reads options from configuration, not a delegate. In `appsettings.json`:
```json
{
  "Rasp": {
    "BlockOnDetection": true,
    "EnableMetrics": true
  }
}
```
```csharp
builder.Services.AddRasp(builder.Configuration);
```
Set `BlockOnDetection` (and the per-engine `BlockOnAdoNetDetection` / `BlockOnSsrfDetection` /
`BlockOnRuntimePatchingDetection`) to `false` for audit/monitor-only mode. See
[`RaspOptions`](src/Rasp.Core/Configuration/RaspOptions.cs) for the full set of options.

**Warning**: Metrics/logging emitted at detection points may include the offending payload
snippet. Ensure logs are secured.

### 4. Scoping File and Process Access
`AllowedFileRoots` and `AllowedProcesses` gate the Phase B runtime-patching guards
(Path Traversal / Command Injection). Note the defaults are asymmetric by design: an empty
`AllowedFileRoots` fails **open** (no path check), while an empty `AllowedProcesses` fails
**closed** (no process may start) — see the XML docs on those properties for the reasoning.
```json
{
  "Rasp": {
    "AllowedFileRoots": ["/var/app/data"],
    "AllowedProcesses": ["/usr/bin/git"]
  }
}
```

### 5. Package Source
RASP.Net is not yet published to NuGet.org — build and reference the packages from source, or
use the local packing scripts (`scripts/pack-local.ps1` / `.sh`) described in
[CHEATSHEET.md](docs/CHEATSHEET.md). See [ROADMAP.md](docs/ROADMAP.md) for NuGet publishing status.

---

## 🧪 Responsible Disclosure Examples

The examples below illustrate the report format we're looking for (issue → repro → suggested
fix), not open vulnerabilities. Example 1 describes a gap that has since been closed — the XSS
engine now multi-pass decodes URL encoding, HTML entities, and Unicode escapes before pattern
matching (see [ADR 005](docs/ADR/005-xss-engine.md)) — kept here as a template for what a good
report looks like.

### Example 1: Bypass via Encoding (historical — fixed)
**Vulnerability**: URL-encoded payloads bypassed inspection because decoding happened after
pattern matching instead of before.
```python
payload = urllib.parse.quote("' OR '1'='1")
```

**Fix**: Decode (URL, HTML entity, Unicode escape) before pattern matching, bounded by a
decode-pass budget to avoid ReDoS-style amplification.

### Example 2: Performance DoS
**Vulnerability**: Complex regex causes ReDoS
```csharp
// Bad: Catastrophic backtracking
Regex.Match(input, @"(a+)+b");
```

**Fix**: Use `RegexOptions.NonBacktracking` (. NET 7+)

---

## 🏆 Hall of Fame

Security researchers who responsibly disclose vulnerabilities will be recognized here (with permission).

| Researcher | Vulnerability | Severity | Date |
|:-----------|:--------------|:---------|:-----|
| *None yet* | - | - | - |

---

## 📚 References

- [OWASP RASP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Runtime_Application_Self_Protection_Cheat_Sheet.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP Top 10](https://owasp.org/Top10/)

---

**Remember**: This is an educational project. Use in production at your own risk. 🚀