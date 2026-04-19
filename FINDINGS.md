# Security Audit Findings: SSH-Relay

This document summarizes the security vulnerabilities identified during a manual review of the `ssh-relay` codebase.

---

## 1. Critical Risk: Server-Side Request Forgery (SSRF)

**Location:** `src/ssh_relay/net.py:open_tcp`  
**Description:**  
The relay accepts arbitrary `host` and `port` parameters from the user via the `/v4/connect` WebSocket endpoint and passes them directly to `asyncio.open_connection` or `socket.connect`.

**Impact:**  
An authenticated user can use the relay to tunnel traffic to internal network resources that the relay server can reach but which are not exposed to the public internet. This includes:
- Local services (e.g., `localhost:22`, `localhost:5432`).
- Internal management interfaces or other backend servers.
- Cloud metadata services (e.g., `169.254.169.254`).

**Recommendation:**  
Implement a configurable allowlist of permitted target CIDRs or hostnames. At a minimum, block connections to private (RFC 1918), link-local, and loopback IP ranges unless explicitly allowed.

---

## 2. High Risk: Cross-Site WebSocket Hijacking (CSWH)

**Location:** `src/ssh_relay/app.py:v4_connect`, `v4_reconnect`  
**Description:**  
The WebSocket endpoints do not validate the `Origin` header of incoming requests.

**Impact:**  
Since the relay can authenticate users via cookies (`CF_Authorization`), a malicious website visited by an authenticated user can initiate a WebSocket connection to the relay. The attacker's site can then proxy SSH traffic through the user's browser, effectively hijacking their session without their knowledge.

**Recommendation:**  
Verify that the `Origin` header matches the expected `RELAY_PUBLIC_HOST`.

---

## 3. High Risk: Denial of Service (DoS) via Memory Exhaustion

**Location:** `src/ssh_relay/app.py:lifespan`, `Session` class  
**Description:**  
There is no limit on the number of concurrent sessions the relay will handle. Each session maintains a 4MiB replay buffer (`RELAY_MAX_REPLAY_BUFFER`) and persists for a grace period (`RELAY_GRACE_SECONDS`) after the WebSocket disconnects.

**Impact:**  
An attacker can open a large number of sessions to rapidly exhaust the server's memory, leading to a denial of service for all users.

**Recommendation:**  
Implement global and per-user limits on the number of concurrent active sessions.

---

## 4. Medium Risk: Session Hijacking in "None" Identity Mode

**Location:** `src/ssh_relay/identity.py:NoneProvider`, `src/ssh_relay/app.py:v4_reconnect`  
**Description:**  
When `RELAY_IDENTITY_PROVIDER` is set to `none`, all users share a `None` identity key. The session reconnection logic validates that the requester's identity matches the session owner: `session.identity_key == identity_key`.

**Impact:**  
In "none" mode, this check effectively becomes `None == None`. Any user who can guess or obtain a valid Session ID (`sid`) can hijack another user's active session.

**Recommendation:**  
Disable "none" mode in production environments. If required for testing, ensure it generates a unique pseudo-identity (e.g., based on source IP) to prevent trivial hijacking.

---

## 5. Medium Risk: Port Pool Exhaustion

**Location:** `src/ssh_relay/ports.py`, `src/ssh_relay/app.py:v4_connect`  
**Description:**  
When source-port pinning is enabled (for PAN User-ID mapping), the relay uses a finite pool of ports.

**Impact:**  
An authenticated user can exhaust the port pool by opening many concurrent sessions, preventing other users from establishing new connections. The `PortPoolExhausted` exception is also unhandled in `v4_connect`, leading to an internal server error.

**Recommendation:**  
Implement per-user limits on sessions that consume ports from the pool and gracefully handle pool exhaustion.

---

## 6. Medium Risk: IP Spoofing in Audit Logs

**Location:** `src/ssh_relay/app.py:_source_ip`  
**Description:**  
The application trusts the `X-Forwarded-For` header without verifying that the request originated from a trusted proxy.

**Impact:**  
An attacker can provide a fake `X-Forwarded-For` header to spoof their source IP in the relay's security logs, complicating incident response and auditing.

**Recommendation:**  
Only trust `X-Forwarded-For` or `cf-connecting-ip` headers when they come from a known, trusted proxy IP range.

---

## 7. Low Risk: Sensitive Information in Logs

**Location:** `src/ssh_relay/sinks.py:PanUserIdSink`  
**Description:**  
The Palo Alto Networks User-ID sink includes the API key in the URL parameters of the POST request.

**Impact:**  
Depending on how the firewall or intermediate proxies log outgoing requests, the `RELAY_PAN_API_KEY` could be exposed in web server access logs or proxy logs.

**Recommendation:**  
If supported by the PAN-OS API, pass the API key via a header rather than a query parameter.
