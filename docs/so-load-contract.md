# SO load contract (protect-so)

Commercial runtime contract for encrypted business SOs. Strategies are
**mechanism-based**, not customer SO basenames.

## Load strategies

| Id | Name | When | Linker `filename` / `dladdr` | File content |
|----|------|------|------------------------------|--------------|
| **L1** | Extract plain | Packaged extract dir is writable; plaintext published there after archiving cipher to `so_cipher/` | `/data/app/.../lib/<abi>/libX.so` | Same path (plaintext) |
| **L2** | Extract name + FD | Extract not writable; plaintext from `so_plain` (or memfd copy) | Extract path string (linker id) | `android_dlopen_ext` + `ANDROID_DLEXT_USE_LIBRARY_FD` → **memfd** when `memfd_create` works and the SO is ≤ 16 MiB; else `so_plain` fd |
| **L2b** | `dladdr` rewrite | After L2/L3 maps still show `so_plain` or `/memfd:` | Hooked `dladdr` returns extract path for keyed SOs | Unchanged |
| **L3** | so_plain path | Fallback when memfd / `android_dlopen_ext` fail | `.../code_cache/protector/so_plain/libX.so` | Same |
| **Skip** | Do not encrypt | Class S / path-sensitive / industry (mode-dependent) | N/A | — |

After a successful **L1** or **L2** map, the keyed `so_plain/libX.so` file is
**kept on disk** so the next process can warm-reuse via `so_plain_ready`
(product chose cross-launch speed over in-process unlink). **L3** also keeps
the file. Class S is never planted in `so_plain/`.

## Plaintext warm cache (`so_plain_ready` + DEX `.prepatched`)

Cross-launch speed by reusing decrypted mirrors (accepts plaintext-at-rest):

| Path | Role |
|------|------|
| `code_cache/protector/so_plain/*` | Decrypted keyed ELF mirrors kept across launches |
| `so_plain/so_plain_ready` | Present when all on-ABI keyed SOs are mirrored |
| `.prepatched` + `classes*.dex` | DEX warm — skip PDX1 re-extract / re-prepatch |

Cold start: RC4 into `so_plain` → write `so_plain_ready` (+ DEX `.prepatched`).  
Next launch: reuse mirrors / prepatched dexes (skip RC4 and dex re-decrypt).  
APK update deletes `so_plain/`, `.prepatched`, and extracted dexes via `invalidateIfApkChanged`.

Legacy `so_warm/` PSW1 helpers may remain in the tree but are not used on this path.

### Hi-MC / HiBoat verification (2026-08)

- **SAFE/MAX + `path_sensitive` skip** (`libd3` / `libzhd3d`): MainMap / DeepSurvey stable.
- **AGGRESSIVE encrypt d3/zhd3d + L2**: still TTIN `SIGSEGV @ 0x30` — do not ship.
- **AGGRESSIVE encrypt `libcrypto*`**: Conscrypt SIGILL (Class S). Packer+runtime
  now refuse Class S in **all** modes including AGGRESSIVE.

Default product modes:

- **SAFE / MAX:** skip Class S (`system_soname`), industry SDKs, and path-sensitive.
- **AGGRESSIVE:** still **hard-skips Class S**; may encrypt path-sensitive / some industry SDKs.

## Class S — system / reserved soname collision

APK-bundled OpenSSL (etc.) must **never** live under `so_plain` or be RC4-encrypted:
`nativeLibraryDir` → `so_plain` would hijack `libcrypto.so` / `libssl.so` and break
Apex Conscrypt (`RSA_new` SIGILL). Same class: Bionic/NDK exact names, GLES/EGL/Vulkan.

| Layer | Behavior |
|-------|----------|
| Packer (all modes) | Skip encrypt; report reason `system_soname` |
| Runtime materialize | Refuse copy/RC4 into `so_plain`; unlink if present |
| Runtime `copy_plain_deps` | Never symlink/plant Class S beside mirrors |
| Runtime dlopen path | Never rewrite Class S to `so_plain`; scrub on sight |

Re-pack old “encrypt everything” APKs; dirty `so_plain/libcrypto*` is scrubbed on next launch.

## Class A — dependency dual-mapping

- Non-keyed deps beside keyed mirrors: **symlink** to packaged extract (same inode).
- Never plant Class S / GLES stubs in `so_plain` (use `/system` / Apex).
- Refresh dep links **before** keyed preload / dlopen.
- `ApplicationInfo.nativeLibraryDir` → `so_plain` when mirrors exist; ClassLoader prepends `so_plain`, packaged extract as fallback for excluded/unkeyed libs.

## Class B — path-sensitive engines

Heuristic (packer), not hard-coded app SO names:

- `.text` size ≥ 4 MiB **or** file size ≥ 16 MiB, and
- `.dynstr` / small `.rodata` scan hits graphics NEEDED stubs (`libGLESv*`, `libEGL`) **or** engine markers (`osg`, `osgDB`, `Unity`, `UE4`, `cocos2d`, …).

Runtime: prefer **L1 → L2 → L3** so `dladdr` stays on the extract path whenever possible (L1/L2).

## Hooks failure

If dlopen-family hooks fail (e.g. bytehook): force full materialize + eager-style preload; never execute packaged ciphertext for keyed SOs.

## Operator overrides

- `--protect-so-exclude` — force skip encrypt (highest priority).
- `--protect-so-mode aggressive` — allow encrypting path-sensitive (not Class S).
