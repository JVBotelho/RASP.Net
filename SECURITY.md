# Security Policy

## 🛡️ Reporting Security Vulnerabilities

**RASP.Net is a security research project.** If you discover a vulnerability in the RASP itself (ironic, we know!), please report it responsibly.

### Where to Report

**DO NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **[rasp.net.passerby434@passinbox.com]** with:

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

1. **No Taint Tracking**: The RASP does not track data flow through variables
   - **Impact**: Obfuscated attacks may bypass detection
   - **Mitigation**: Defense-in-depth approach (detect at entry + sink)

2. **Signature-Based Detection**: Uses regex patterns, not behavioral analysis
   - **Impact**: Novel/zero-day attacks may not be detected
   - **Mitigation**: Regular pattern updates

3. **Performance Overhead**: All interception adds latency
   - **Impact**: ~3-5% throughput reduction in high-load scenarios
   - **Mitigation**: Benchmarking tools provided

### Attack Vectors NOT Currently Covered

- ❌ NoSQL Injection (MongoDB, Cosmos DB)
- ❌ LDAP Injection
- ❌ XML External Entity (XXE)
- ❌ Server-Side Template Injection (SSTI)
- ⚠️ XSS (Partial: only in gRPC string fields)

---

## 🔐 Security Best Practices for Users

If you're deploying RASP.Net in a test/production environment:

### 1. Defense in Depth
RASP is **not a replacement** for:
- Input validation at API boundaries
- Parameterized queries (use EF Core correctly!)
- Web Application Firewalls (WAF)
- Network segmentation

### 2. Logging and Monitoring
```csharp
builder.Services.AddRasp(options =>
{
    options.EnableDetailedLogging = true; // ⚠️ May log sensitive data
    options.BlockMode = true; // false = monitor-only mode
});
```

**Warning**: Detailed logging may capture sensitive data in payloads. Ensure logs are secured.

### 3. False Positive Handling
Add legitimate patterns to allowlist:
```json
{
  "Rasp": {
    "Allowlist": {
      "Patterns": [
        "SELECT * FROM Users WHERE Name = 'O''Reilly'"
      ]
    }
  }
}
```

### 4. Regular Updates
```bash
# Check for updates
dotnet list package --outdated

# Update RASP packages
dotnet add package Rasp.Core --version 1.x.x
```

---

## 🧪 Responsible Disclosure Examples

### Example 1: Bypass via Encoding
**Vulnerability**: URL-encoded payloads bypass gRPC interceptor
```python
payload = urllib.parse.quote("' OR '1'='1")
# RASP doesn't decode before inspection
```

**Fix**: Add URL decoding before pattern matching

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