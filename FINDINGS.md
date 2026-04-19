# Security Audit Findings: SSH-Relay

This document summarizes the security vulnerabilities identified during the review and their current resolution status.

---

## 1. Critical Risk: Server-Side Request Forgery (SSRF)

**Status:** ✅ RESOLVED  
**Location:** `src/ssh_relay/target_policy.py`, `src/ssh_relay/app.py`  
**Description:**  
Originally, the relay allowed connections to any host/port.

**Resolution:**  
Implemented a `TargetPolicy` that resolves hostnames and validates all IP addresses against a denylist.
- **Built-in Deny:** Loopback, link-local (cloud metadata), multicast, and reserved ranges are blocked by default.
- **Allowlist:** Operators can optionally restrict connections to specific CIDRs using `RELAY_TARGET_ALLOWLIST`.
- **DNS Rebinding Protection:** The application now connects to the validated IP address directly, preventing TOCTOU DNS rebinding attacks.

---

## 2. High Risk: Cross-Site WebSocket Hijacking (CSWH)

**Status:** ✅ RESOLVED  
**Location:** `src/ssh_relay/app.py:_check_origin`  
**Description:**  
The WebSocket endpoints did not validate the `Origin` header.

**Resolution:**  
Added an `Origin` check against a configurable allowlist (`RELAY_ALLOWED_ORIGINS`). By default, it permits the official `nassh` extension IDs.

---

## 3. High Risk: Denial of Service (DoS) via Memory Exhaustion

**Status:** ✅ RESOLVED  
**Location:** `src/ssh_relay/app.py`  
**Description:**  
Lack of limits on concurrent sessions allowed for memory exhaustion.

**Resolution:**  
Implemented global and per-identity session caps:
- `RELAY_MAX_SESSIONS_TOTAL` (default 1000)
- `RELAY_MAX_SESSIONS_PER_IDENTITY` (default 100)
Requests exceeding these caps are rejected with WebSocket code `4429`.

---

## 4. Medium Risk: Session Hijacking in "None" Identity Mode

**Status:** ✅ MITIGATED  
**Location:** `src/ssh_relay/app.py:_build_identity`  
**Description:**  
"None" mode allowed unauthenticated access and potential session hijacking.

**Resolution:**  
- The application now requires an explicit contradiction acknowledgment: `RELAY_IDENTITY_PROVIDER=none` must be paired with `RELAY_AUTH_REQUIRED=false`, or it will fail to start.
- Documentation and code comments now emphasize that "none" mode is for development or trusted-proxy deployments only.

---

## 5. Medium Risk: Port Pool Exhaustion

**Status:** ✅ RESOLVED  
**Location:** `src/ssh_relay/app.py:v4_connect`, `src/ssh_relay/ports.py`  
**Description:**  
The port pool could be exhausted by a single user, and the exhaustion was unhandled.

**Resolution:**  
- The `v4_connect` endpoint now gracefully catches `PortPoolExhausted` and returns a `4503` code.
- Per-identity session caps (Finding #3) prevent a single user from easily exhausting the pool.

---

## 6. Medium Risk: IP Spoofing in Audit Logs

**Status:** ✅ RESOLVED  
**Location:** `src/ssh_relay/app.py:_source_ip`  
**Description:**  
The application trusted `X-Forwarded-For` from any peer.

**Resolution:**  
Implemented a `trusted_proxies` allowlist. Headers like `X-Forwarded-For` and `CF-Connecting-IP` are now only trusted if the immediate peer IP matches a configured CIDR in `RELAY_TRUSTED_PROXIES`.

---

## 7. Low Risk: Sensitive Information in Logs

**Status:** ℹ️ ACKNOWLEDGED  
**Location:** `src/ssh_relay/sinks.py:PanUserIdSink`  
**Description:**  
API key passed as query parameter to PAN-OS.

**Note:**  
This is a requirement of the PAN-OS XML API for certain operations. Operators should ensure that logs for the relay's outbound traffic are appropriately secured.
