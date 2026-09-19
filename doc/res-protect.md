# Phase 2B — Res path obfuscation (`--enable-res-protect`)

**Status:** done.

## Behavior

| Item | Detail |
|------|--------|
| Opt-in | `--enable-res-protect` / `--res-protect` (default **OFF**) |
| Availability | Desktop ExtraProtect UI collapsed; enable via **packer CLI** only for now |
| Scope | File-backed `res/**` paths found in `resources.arsc` global string pool |
| Rewrite | Short paths `res/drawable-xxhdpi/foo.png` → `r/a/b.png` |
| Arsc | In-place string-pool replace (new path must fit old slot) |
| Keep | Arsc stays **STORED** (mmap); **not encrypted** (see Phase 2C deferred) |
| Whitelist | Default keeps `res/mipmap*/**` (launcher icons) |
| Mapping | `assets/protector/res_mapping.txt` |

Resource **IDs** and binary XML `@drawable/...` references are unchanged — only on-disk / pool path strings shorten (AndResGuard-style).

## Out of scope

- Encrypting `resources.arsc` (high risk; deferred)
- Obfuscating resource *names* in type/key pools (`R.string.foo` → `a`)
- 7zip repack

## Verify

```powershell
.\gradlew.bat protectDemo
# expect: res-protect: paths=N arsc_rewritten=N files_moved=N
# unzip demo-protected.apk → look for r/a/... and assets/protector/res_mapping.txt
```
