# PVM2 compatibility matrix

Source of truth: `Pvm2Compiler.translateOne` switch (Dalvik opcode → PVM2).  
This is **admission telemetry**, not a promise to widen True-VMP. Unsupported methods fall back to hollow / PVM1.

Status:

- **yes** — compiled
- **no** — `unsupported opcode 0xNN` (method skipped)
- **unused** — not a real Dalvik opcode in current ART

Do **not** change `PaymentVmpRules` / `IndustryVmpRules` / BALANCED hollow defaults from this table.

Packer prints:

```text
PVM2 admission: candidates=N attempted=A success=S fallback=F rate=xx.x%
PVM2 skip reasons: unsupported_opcode=… too_many_regs=… try_catch=… branch=… type=… other=…
TRUE_VMP unsupported opcodes (count): {0xNN=count, …}
```

Use the opcode histogram to pick the next 1–2 ISA holes. **Do not add opcodes from guesswork.** `0x2c sparse-switch` still has no fail-histogram hits. `0x2b packed-switch` and `0x26 fill-array-data` are lowered to existing PVM2 ops (no new opcode / morph table size).

Limits that are not opcodes (skip reason in parentheses):

| Check | Limit | Reason |
|---|---|---|
| registers + scratch | 32 | `too_many_regs` |
| code units | 512 | `other` (`too large`) |
| return type | V/I/J/F/D/Z/L | `type` |
| try/catch mapping | handlers must map to emits | `try_catch` |
| branch fixup | 16-bit PVM2 rel | `branch` |

Try/catch **is implemented** (`buildHandlers`). `try_catch` counts mapping failures, not “no exception ISA”.

## Move / result / return

| Op | Name | Status |
|---|---|---|
| 0x00 | nop | yes |
| 0x01 | move | yes |
| 0x02 | move/from16 | yes |
| 0x03 | move/16 | **no** |
| 0x04 | move-wide | yes |
| 0x05 | move-wide/from16 | yes |
| 0x06 | move-wide/16 | **no** |
| 0x07 | move-object | yes |
| 0x08 | move-object/from16 | yes |
| 0x09 | move-object/16 | **no** |
| 0x0a–0x0d | move-result* / move-exception | yes |
| 0x0e–0x11 | return* | yes |

## Const

| Op | Name | Status |
|---|---|---|
| 0x12–0x15 | const / const/4 / const/16 / const/high16 | yes |
| 0x16–0x19 | const-wide* | yes |
| 0x1a–0x1b | const-string* | yes |
| 0x1c | const-class | yes |

## Monitor / type / new / array

| Op | Name | Status |
|---|---|---|
| 0x1d–0x1e | monitor-enter/exit | yes |
| 0x1f | check-cast | yes |
| 0x20 | instance-of | yes |
| 0x21 | array-length | yes |
| 0x22 | new-instance | yes |
| 0x23 | new-array | yes |
| 0x24 | filled-new-array | yes |
| 0x25 | filled-new-array/range | yes |
| 0x26 | fill-array-data | yes (lowered to CONST+APUT) |
| 0x27 | throw | yes |

## Control

| Op | Name | Status |
|---|---|---|
| 0x28 | goto | yes |
| 0x29 | goto/16 | yes |
| 0x2a | goto/32 | **no** |
| 0x2b | packed-switch | yes (lowered to CONST+IF_EQ) |
| 0x2c | sparse-switch | **no** |
| 0x2d–0x31 | cmpl/cmpg-float/double, cmp-long | yes |
| 0x32–0x37 | if-test | yes |
| 0x38–0x3d | if-testz | yes |
| 0x3e–0x43 | unused | unused |

## Array / instance / static field

| Op | Name | Status |
|---|---|---|
| 0x44–0x4a | aget-* | yes |
| 0x4b–0x51 | aput-* | yes |
| 0x52–0x58 | iget-* | yes |
| 0x59–0x5f | iput-* | yes |
| 0x60–0x66 | sget-* | yes |
| 0x67–0x6d | sput-* | yes |

## Invoke

| Op | Name | Status |
|---|---|---|
| 0x6e–0x72 | invoke-{virtual,super,direct,static,interface} | yes |
| 0x73 | unused | unused |
| 0x74–0x78 | invoke-*/range | yes |
| 0x79–0x7a | unused | unused |
| 0xfa | invoke-polymorphic | **no** |
| 0xfb | invoke-polymorphic/range | **no** |
| 0xfc | invoke-custom | **no** |
| 0xfd | invoke-custom/range | **no** |

## Unop / binop / lit

| Op | Name | Status |
|---|---|---|
| 0x7b–0x8f | neg/not/int-to-* / *-to-* | yes |
| 0x90–0xaf | binop (int/long/float/double) | yes |
| 0xb0–0xcf | binop/2addr | yes |
| 0xd0–0xd7 | binop/lit16 | yes |
| 0xd8–0xe2 | binop/lit8 | yes |
| 0xe3–0xf9 | execute-inline / invoke-object-init / … | **no** |
| 0xfe | const-method-handle | **no** |
| 0xff | const-method-type | **no** |

## Observed (protectDemo, 2026-09-11)

Command: `.\gradlew.bat protectDemo`  
Scope: True-VMP candidates only (`--true-vmp-prefix Lcom/yqsh/protectordemo/Business;`). Payment auto-VMP: types=0 methods=0. Not a whole-APK opcode census.

```text
PVM2 admission: candidates=14 attempted=14 success=14 fallback=0 rate=100.0%
PVM2 skip reasons: unsupported_opcode=0 too_many_regs=0 try_catch=0 branch=0 type=0 other=0
TRUE_VMP unsupported opcodes (count): {}
```

The opcode line was omitted in that pack (empty map). Packer now always prints `{}` when there are no unsupported opcodes.

Admitted `Business` methods (14/14): `add`, `arrayProbe`, `catchProbe`, `doubleProbe`, `fieldProbe`, `floatCastProbe`, `floatCmpProbe`, `floatProbe`, `invokeProbe`, `licenseScore`, `longShiftProbe`, `secret`, `soProbe`, `syncProbe`. (`nativeAddRaw` is `external`, not a compile candidate.)

Demo `Business` was written to stay inside the current ISA (invoke / field / array / try-catch / float / monitor / long-shift). A 100% rate here does **not** mean those ISA holes are unused in customer APKs.

## Observed (Hi-MC V1.3.1.3, 2026-09-11)

APK: `E:\C++\11\Hi-MC_V1.3.1.3.apk` (`com.zhd.mech.himc`, 12 DEX). Same `Pvm2Compiler` as packer; not a full 241MB repack.

**Production default (payment auto-VMP):** types=0, candidates=0. No `alipay` / `/wxapi/` types.

**`--profile industry` tokens under `Lcom/zhd/mech/himc/`:** types=0.

**If `--true-vmp-prefix Lcom/zhd/mech/himc/`** (255 types, 900 methods with code, excluding `<init>`/`<clinit>`):

Before PR10:

```text
PVM2 admission: candidates=900 attempted=900 success=894 fallback=6 rate=99.3%
PVM2 skip reasons: unsupported_opcode=1 too_many_regs=3 try_catch=0 branch=0 type=0 other=2
TRUE_VMP unsupported opcodes (count): {0x2b=1}
```

The ISA-hole skip was `DiagnoseViewModel$diagnoseAll$1;->invokeSuspend` (`packed-switch`). Other fallbacks are not opcodes: databinding `bind` / `getComponents` (`too_many_regs`); two methods `too large` (>512 code units). `0x26` and `0x2c` did not appear.

After PR10 (`0x2b` lowered to CONST+IF_EQ):

```text
PVM2 admission: candidates=900 attempted=900 success=895 fallback=5 rate=99.4%
PVM2 skip reasons: unsupported_opcode=0 too_many_regs=3 try_catch=0 branch=0 type=0 other=2
TRUE_VMP unsupported opcodes (count): {}
```

`invokeSuspend` is now admitted. Remaining 5 skips are still regs/size.

## Observed (一起守护家长端 1.0.0, 2026-09-11)

APK: `E:\Android\TestDemo\guradianparents\app\release\app-release.apk` (`com.togeter.play`, 1 DEX, ~45MB).

**Production default (payment auto-VMP):** 363 Alipay types, 1294 candidates.

Before `0x26`:

```text
PVM2 admission: candidates=1294 attempted=1285 success=1277 fallback=8 rate=99.4%
PVM2 skip reasons: unsupported_opcode=2 too_many_regs=0 try_catch=0 branch=0 type=0 other=6
TRUE_VMP unsupported opcodes (count): {0x26=2}
```

After `0x26` lowered to CONST+APUT:

```text
PVM2 admission: candidates=1294 attempted=1285 success=1279 fallback=6 rate=99.5%
PVM2 skip reasons: unsupported_opcode=0 too_many_regs=0 try_catch=0 branch=0 type=0 other=6
TRUE_VMP unsupported opcodes (count): {}
```

`l0/a;->a` and `n0/d;->a` are now admitted. Remaining 6 skips are `too large`.

Dalvik 0x26/0x2b/0x2c in those candidates (instruction count): `0x26=2` `0x2b=6` `0x2c=1`.

| Op | In fail histogram? | Notes |
|---|---|---|
| 0x26 fill-array-data | no (admitted) | 2 methods, compiled via CONST+APUT |
| 0x2b packed-switch | no (PR10 admits) | 6 methods |
| 0x2c sparse-switch | no | 1 insn in `Lcom/alipay/sdk/m/x/d;->a`, but that method is `too large` (>512) so the compiler never reports 0x2c |

**App prefix `Lcom/togeter/play/`:** 799 methods, histogram `{}`. No 0x26/0x2b/0x2c. 5 skips are size/regs.

## Next opcode work (gated on histogram)

1. `0x2b` and `0x26` are done (lowered; no new PVM2 opcode). Payment / industry / BALANCED rules unchanged.
2. **Do not implement `0x2c` from this harvest** (the only sparse-switch method is already skipped as too large).
3. Next ISA work needs a new non-empty `TRUE_VMP unsupported opcodes` histogram.
4. Do not widen payment/industry rules in an opcode change.
