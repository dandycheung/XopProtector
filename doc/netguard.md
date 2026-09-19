# Phase 3 — NetGuard (proxy/VPN detect + cert pinning helpers)

**Status:** implemented (opt-in).

## CLI

| Flag | Default | Meaning |
|------|---------|---------|
| `--detect-proxy` | OFF | Write `netguard.json` with proxy+VPN heuristics |
| `--pin-certs <file>` | none | Leaf cert SHA-256 hex pins (one per line, `#` comments) |

Also sets `config.json` fields `detect_proxy` / `net_guard` (HMAC-covered).

## Runtime

- `NetGuard.install(Context)` from shell bootstrap
- Proxy/VPN hit → soft `JniBridge.reportThreat` (record + optional degrade; **no Block crash**)
- Pinning: `NetGuard.wrappingTrustManager(base)` for app HTTPS stacks
- **Not** the same as `verifySignature` (APK signing cert)

## Availability

Default **OFF**. `protectDemo` and Desktop ExtraProtect UI do **not** enable NetGuard;
use packer CLI when needed (`--detect-proxy`, `--pin-certs <file>`).

## Usage (app)

```java
// After shell bootstrap (automatic):
X509TrustManager pinned = NetGuard.wrappingTrustManager(systemTm);
NetGuard.rescan(context); // before sensitive calls
```
