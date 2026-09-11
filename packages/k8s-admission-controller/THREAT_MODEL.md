# Threat Model: Kubernetes Validating Admission Controller (`@ai-security-architect/k8s-admission-controller`)

## 1. System Overview & Architecture
The `ai-security-architect` Kubernetes Admission Controller operates as a live, runtime-critical `ValidatingAdmissionWebhook`. It is registered in the Kubernetes cluster via a `ValidatingWebhookConfiguration` and is invoked synchronously by `kube-apiserver` over HTTPS on `POST /validate` whenever relevant Kubernetes resources (`Pod`, `Deployment`, `ClusterRole`, etc.) are created or updated.

The controller evaluates incoming resource manifests against precomputed security budgets and policies without performing inline repo-wide graph rescans.

---

## 2. Trust Boundaries & Attack Surfaces

```
+-------------------------------------------------------------+
|                     Kubernetes Cluster                      |
|                                                             |
|  +--------------------+         mTLS          +-----------+ |
|  |   kube-apiserver   |  =================>   |  Webhook  | |
|  +--------------------+  <=================   |  Server   | |
|                                               +-----+-----+ |
|                                                     |       |
|                                             Internal Evaluation
|                                                     |       |
|                                               +-----v-----+ |
|                                               | WORM Audit| |
|                                               | Logger    | |
|                                               +-----------+ |
+-------------------------------------------------------------+
```

1. **Inbound HTTP Surface (`/validate`)**:
   - Reachable only from `kube-apiserver` pods over cluster network.
   - Accepts JSON `AdmissionReview` payloads.
2. **Execution Environment**:
   - Pod running within the cluster (e.g., `sec-arch-system` namespace).
3. **Outbound Dependencies**:
   - Local WORM audit log (filesystem / SQLite).
   - Read-only ConfigMap for policy updates.

---

## 3. Threat Scenarios, Failure Modes & Mitigations

### Threat 1: Malicious / Crafted AdmissionRequest Payload
- **Threat Actor**: Malicious or compromised cluster tenant submitting an intentionally deformed manifest.
- **Attack Vectors**:
  - Oversized JSON payloads intended to exhaust webhook memory.
  - Deeply nested objects or prototype-pollution keys.
  - ReDoS (Regular Expression Denial of Service) in field names or container arguments.
- **Impact**: Webhook CPU exhaustion or OOM crash, causing latency spikes for all cluster deployments.
- **Mitigations**:
  - **Body Size Limit**: Hard 1MB payload ceiling enforced at HTTP stream ingestion (`413 Payload Too Large`).
  - **Timeout Circuit Breaker**: Synchronous evaluation aborts after 150ms (`timeoutMs: 150`).
  - **Schema Sandboxing**: Safe JSON parsing with prototype pollution guards and non-backtracking regular expressions.

---

### Threat 2: Webhook Unavailability & Deployment Freezes (Denial of Service)
- **Failure Mode**: The webhook pod crashes, becomes network partitioned, or experiences severe GC pauses.
- **Impact**:
  - If `failurePolicy: Fail` (fail-closed), **every deployment across the cluster freezes**. Emergency patches and hotfixes cannot be deployed.
- **Mitigations**:
  - **Default Fail-Open**: The webhook defaults strictly to `failurePolicy: Ignore` and emits loud alert logs if invoked during degraded states.
  - **Audit-Only / Dry-Run Default**: The controller defaults to `mode: "dry-run"`, where all resources are allowed (`allowed: true`) while logging policy violations with `[DRY-RUN SECURITY WARNING]`.
  - **Strict Latency Budget**: Evaluates against in-memory cached rules with zero blocking I/O or network roundtrips during admission processing.

---

### Threat 3: Webhook Compromise & Privilege Escalation
- **Threat Actor**: Advanced attacker with cluster access attempting to compromise the webhook pod to bypass security gates.
- **Impact**: Attacker could selectively allow malicious container specs or inject unauthorized workloads.
- **Mitigations**:
  - **Read-Only Root Filesystem**: Container root filesystem is mounted read-only (`readOnlyRootFilesystem: true`).
  - **Non-Root Execution**: Runs as unprivileged UID 10001 (`runAsNonRoot: true`).
  - **Dropped Capabilities**: All Linux capabilities dropped (`capabilities: { drop: ["ALL"] }`).
  - **Minimal RBAC**: The ServiceAccount for the webhook has zero write permissions to any cluster resource. It has read-only access exclusively to its own ConfigMap. It cannot read Secrets or other pods' specs.
  - **mTLS Verification**: Webhook requires mutual TLS (mTLS) with client certificate verification validated against the cluster Certificate Authority.

---

### Threat 4: Unauthorized Impersonation & Forgery
- **Threat Actor**: Internal attacker attempting to POST fake admission reviews to flood audit logs or probe rules.
- **Impact**: Audit log pollution, false compliance reports.
- **Mitigations**:
  - Webhook binds only to cluster internal network interface.
  - HTTPS enforced with mandatory client certificate validation (`clientAuth: RequireAndVerifyClientCert`).

---

### Threat 5: Audit Log Tampering
- **Threat Actor**: Malicious actor seeking to erase evidence of denied deployment attempts.
- **Impact**: Loss of non-repudiation and forensic visibility.
- **Mitigations**:
  - Every decision (ALLOW, DENY, DRY_RUN_DENY, TIMEOUT_FAIL_OPEN) is piped directly to `WormAuditLogger` using SHA-256 hash chaining with previous block verification.

---

## 4. Blast Radius Assessment

| Failure Mode | Default Blast Radius | Worst-Case Blast Radius (Mitigated) |
|---|---|---|
| Webhook Process Crash | Zero deployment impact (`fail-open` allows pods) | Temporary lack of admission enforcement (alert triggered) |
| Rule Misconfiguration | Zero blocking in `dry-run` mode | False positive denials in `enforce` mode (revertible via ConfigMap) |
| Webhook Pod Compromise | Contained inside unprivileged container with no RBAC write access | Attacker cannot modify other workloads or access cluster secrets |
