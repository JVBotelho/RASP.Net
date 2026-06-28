# 🛡️ Threat Model & Attack Scenarios: RASP.Net

## 1. Executive Summary
This document outlines the threat landscape targeting high-performance .NET applications (Game Backends/Real-Time APIs) and how **RASP.Net** mitigates specific attack vectors that traditional WAFs miss.

**Perspective:** Purple Team (Attacker-First Design validated against Defense constraints).
**Scope:** `LibrarySystem.Api` (Proxy for Game Inventory/Economy Service).
**Security Level:** Hardened (Zero-Trust).

---

## 2. Attack Surface Analysis

### 🚨 Scenario A: Economy Manipulation via gRPC SQL Injection
**Threat Actor:** Malicious Player / Script Kiddie
**Goal:** Modify inventory state, duplicate items, or corrupt economy tables.
**Method:**
Attackers utilize `grpcio-tools` to bypass client-side validation and send raw Protobuf messages containing SQL payloads injected into string fields.

#### Why WAFs Fail:
1.  **Binary Obfuscation:** Payloads are serialized in Protobuf. Standard WAFs often fail to decode deep nested binary fields in real-time.
2.  **Encoding Evasion:** Attackers use double-encoding or SQL comments (`/**/`) that look like noise to network filters but are valid for the DB engine.

#### 🛡️ RASP Defense Strategy (Layer 7)
The **Zero-Allocation Detection Engine** intercepts the request **after** deserialization but **before** business logic execution.

* **Detection:** `SqlInjectionDetectionEngine.cs`
* **Technique:**
    1.  **Normalization:** `StackAlloc` buffer normalizes input (lowercasing, whitespace removal) without Heap Allocations.
    2.  **Heuristics:** Scans for token combinations (`union select`, `drop table`) using `Span<T>` search.
    3.  **Outcome:** If `RiskScore >= 1.0`, the request is blocked instantly inside the process memory.

---

### 🕵️ Scenario B: Runtime Tampering (Anti-Cheat)
**Threat Actor:** Reverse Engineer / Cheat Developer
**Goal:** Analyze memory layout, hook functions, or freeze threads to manipulate runtime variables (e.g., God Mode, Currency Freeze).
**Method:**
Attaching managed (Visual Studio) or native (x64dbg, Cheat Engine) debuggers to the running process.

#### 🛡️ RASP Defense Strategy (Layer 0)
The **Native Integrity Guard** serves as a sentinel for the process environment.

* **Detection:** `NativeGuard.cs` (P/Invoke) -> `Guard.cpp` (Native Win32).
* **Technique:** Checks PEB (Process Environment Block) and Debug Ports.
* **Business Impact:** Prevents development of "Trainers" and protect Game Economy integrity.

---

### 📉 Scenario C: Denial of Service (DoS) via GC Pressure
**Threat Actor:** Competitor / Griefer
**Goal:** Degrade server performance (Lag Switching) by forcing Garbage Collection pauses.
**Method:**
Sending thousands of requests with large strings designed to trigger massive allocations during security analysis.

#### 🛡️ RASP Defense Strategy (Performance Engineering)
* **Zero-Allocation Hot Path:** Safe requests (99% of traffic) use cached results and `stackalloc` buffers.
* **No `new String()`:** Analysis is performed on `ReadOnlySpan<char>` views.
* **Target:** Analysis overhead < 100ns per request (measured via BenchmarkDotNet).

---

## 3. STRIDE Analysis Matrix

| Threat Category | Attack Vector | RASP Mitigation | Status |
| :--- | :--- | :--- | :--- |
| **S**poofing | Client Impersonation | gRPC Interceptor Auth Check | 🚧 Planned |
| **T**ampering | **Protobuf Payload Injection** | **Deep Inspection (Pre-Execution)** | ✅ **Implemented** |
| **T**ampering | **Command Injection** (`Process.Start`) | Runtime-patched executable allowlist ([ADR 006](ADR/006-sink-instrumentation-strategy.md) Phase B) | ✅ **Implemented** |
| **T**ampering | **Path Traversal** (`FileStream`/`File.*`) | Runtime-patched canonical-path boundary check (ADR 006 Phase B) | ✅ **Implemented** |
| **R**epudiation | Action without trace | OpenTelemetry Tracing | ✅ Implemented |
| **I**nformation Disclosure | **SQLi Data Exfiltration** | **Heuristic Blocking** at the EF Core/ADO.NET sink | ✅ **Implemented** |
| **I**nformation Disclosure | **SSRF** (internal/metadata endpoint access) | `HttpClient` sink: private-IP/metadata-IP block + DNS-rebinding check | ✅ **Implemented** |
| **I**nformation Disclosure | **Insecure Deserialization** | Type allow/deny guard on `BinaryFormatter`/`TypeNameHandling` | ✅ **Implemented** |
| **D**enial of Service | **GC Heap Exhaustion** | **Zero-Allocation Engine** | ✅ **Implemented** |
| **E**levation of Privilege | **Runtime Memory Hooking** | **Native Integrity Guard** | ✅ **Implemented** |

---

## 4. Exploitation Walkthrough (Red Team Validation)

To validate the defense, we developed a Python exploit script mocking a compromised client.

### 4.1. Attack Setup
Generating the gRPC stubs from the `.proto` definition:
```bash
python -m grpc_tools.protoc -I./protos --python_out=./attack --grpc_python_out=./attack library.proto
```

### 4.2 The Exploit (`attack/exploit_grpc.py`)

This script attempts to inject a SQL payload into the CreateBook method.
```python
# Simplified snippet from attack/exploit_grpc.py
import grpc
import library_pb2_grpc as pb2_grpc

channel = grpc.insecure_channel('localhost:5001')
stub = pb2_grpc.LibraryStub(channel)

# Payload: Attempt to inject generic SQL logic
malicious_title = "' OR '1'='1" 

try:
    response = stub.CreateBook(library_pb2.CreateBookRequest(
        title=malicious_title, 
        author="Hacker", 
        publication_year=2025
    ))
    print(f"Server Response: {response}")
except grpc.RpcError as e:
    print(f"Attack Blocked: {e.details()}")
```
### 4.3. RASP Response (Log Output)

When the exploit runs, the RASP intercepts and blocks execution:
```JSON
{
  "timestamp": "2026-02-02T20:30:00Z",
  "level": "Warning",
  "message": "⚔️ RASP SQLi Blocked! Score: 1.5",
  "data": {
    "threat_type": "SQL Injection",
    "score": 1.5,
    "snippet": "' OR '1'='1"
  }
}
```

## 5. Known Limitations & Mitigation Strategy

| Limitation | Risk | Current Mitigation | Future Enhancement | Risk Acceptance |
|:-----------|:-----|:------------------|:------------------|:----------------|
| **Native DLL Unhooking** | Attackers with kernel access could unload `Rasp.Native.Guard.dll` from process memory | None — `Rasp.Native.Guard.dll` is not Authenticode-signed today | Authenticode signing + self-checksum validation + heartbeat monitoring | ⚠️ Accepted for PoC (requires kernel privileges) |
| **Time-Based Blind SQLi** | Inference attacks via response time analysis | Blocked by keyword matching (`SELECT`, `CASE`) | Random jitter injection in interceptor pipeline | ⚠️ Accepted (low probability in gRPC context) |
| **Polyglot Payloads** | Context-aware exploits valid in multiple languages (SQL+NoSQL+OS) | Per-vector engines (SQL, XSS, SSRF, Path Traversal, Command Injection, Deserialization) | Cross-engine correlation + ML anomaly detection | ⚠️ Accepted (covers real-world threats mapped to OWASP Top 10; see [ROADMAP.md](ROADMAP.md)) |
| **NoSQL Injection** | MongoDB/Cosmos DB query injection | Not currently covered | Dedicated NoSQL detection engine (unscheduled) | ❌ Not Implemented |

**Legend**:
- ✅ Fully Mitigated
- ⚠️ Partially Mitigated / Risk Accepted
- ❌ Not Implemented