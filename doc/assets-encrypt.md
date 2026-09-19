# Phase 2A — Assets encryption (`--encrypt-assets`)

**Status:** implemented (opt-in). **Default OFF** in packer, `protectDemo`, and Desktop UI.

## Important

- There is **no** transparent `AssetManager` hook.
- After `--encrypt-assets`, plaintext paths under `assets/**` are removed; ciphertext lives at `assets/protector/aenc/<relpath>`.
- The app **must** read encrypted assets via `ProtectorAssets` (or `JniBridge.decryptAssetBlob`). Plain `AssetManager.open("…")` will fail (`FileNotFoundException`) — do **not** enable this flag for third-party APKs that still use stock AssetManager.
- Desktop ExtraProtect panel is collapsed; enable via **packer CLI** only when the app is integrated.

## Behavior

| Item | Detail |
|------|--------|
| Opt-in | `--encrypt-assets` / `--no-encrypt-assets` (default **OFF**) |
| Scope | All files under `assets/**` except `assets/protector/**` |
| Skip | `assets/protector/**`, `assets/dexopt/**`, media needing `openFd` |
| Cipher | `PAS1 \|\| AES-GCM(nonce\|\|ct\|\|tag)` |
| Storage | `assets/protector/aenc/<relpath>` (original deleted) |
| Index | `assets/protector/assets.map` |
| Key | `PROTECTOR_ASSETS_KEY` in `libprotector.so` (XOR-padded) |
| Config | `"encrypt_assets":true` inside HMAC payload |

## App API

```java
String s = ProtectorAssets.readString(context, "secret.txt");
InputStream in = ProtectorAssets.open(context, "config/app.json");
```

Do **not** use `AssetManager.open("secret.txt")` after encryption — path moved under `protector/aenc/`.

## CLI (Desktop UI off)

```text
java -jar protector-packer.jar app.apk -o out.apk --shell-dir … \
  --encrypt-assets
```

Related opt-in flags (also Desktop-hidden; CLI only for now):

- `--enable-res-protect` — see `doc/res-protect.md`
- `--detect-proxy` / `--pin-certs <file>` — see `doc/netguard.md`

## Out of scope (later)

- `resources.arsc` encryption (Phase 2C — deferred; high risk)
- Transparent `AssetManager` hook

Res path shortening is **Phase 2B** — see `doc/res-protect.md`.

## Verify (when intentionally enabled)

```powershell
# Manual CLI pack with --encrypt-assets; app must call ProtectorAssets.
# expect: assets encrypt: 0/N … 100%; encrypt_assets=true
```
