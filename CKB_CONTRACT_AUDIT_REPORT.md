# CKB-BLST-RS Contract Audit Report

**Project**: ckb-blst-rs (BLS12-381 Cryptographic Library for CKB-VM)  
**Date**: 2026-03-02  
**Methodology**: CKB Contract Test Analysis Framework  
**Scope**: Full repository — C core, Rust FFI bindings, CKB-VM integration, build system, CI/CD  

---

## 1. Project Overview

`ckb-blst-rs` is a fork/adaptation of the [blst](https://github.com/supranational/blst) BLS12-381 cryptographic library (by Supranational LLC), with added support for CKB-VM (RISC-V `riscv64imac-unknown-none-elf` target). It is designed to be used as a dependency inside CKB smart contracts (Lock/Type scripts) to provide BLS signature operations on-chain.

### 1.1 Architecture Layers

| Layer | Language | Description |
|-------|----------|-------------|
| C Core (`src/`) | C | BLS12-381 field arithmetic, curve ops, pairing, SHA-256, HKDF keygen |
| RISC-V Assembly (`src/asm/*.riscv.S`) | ASM | Optimized Montgomery multiplication for CKB-VM |
| Rust Bindings (`bindings/rust/`) | Rust | FFI wrappers, high-level BLS API (`min_pk`, `min_sig` modules) |
| CKB Example (`bindings/rust-examples/ckb/`) | Rust | Example CKB contract using `ckb-blst` with `ckb-std` |
| Build System (`build.rs`) | Rust | Cross-compilation for RISC-V with CKB-VM defines |

### 1.2 Features

- `ckb-vm` (default): Builds for RISC-V CKB-VM target
- `portable`: No ISA extensions
- `force-adx`: Enable ADX for x86_64
- `std`: Enable standard library (disabled by default for `no_std`)

---

## 2. CKB Transaction Structure Context

Per CKB's UTXO model, this library would be used within Lock or Type scripts to verify BLS12-381 signatures as part of transaction validation.

### 2.1 Cell Structure for BLS-Verified Contracts

When this library is deployed as part of a CKB contract, the typical Cell structure is:

```typescript
type BlsCellArgs {
    lock_args: Bytes,        // BLS public key or hash thereof (for Lock scripts)
    type_args: Bytes,        // Application-specific parameters (for Type scripts)
    data: Bytes,             // Application data protected by BLS verification
    witness: Bytes,          // BLS signature(s) for authorization
}
```

### 2.2 Contract API Analysis

The library does **not** directly use CKB syscalls. Instead, it provides cryptographic primitives that CKB contracts call after loading data via syscalls. The example contract (`bindings/rust-examples/ckb/src/main.rs`) demonstrates the pattern:

**Data Access Pattern (from contract caller)**:
```rust
// 1. Load public keys from cell data or args (via ckb_load_cell_data / ckb_load_script)
// 2. Load signatures from witnesses (via ckb_load_witness)
// 3. Load message to verify (from transaction hash or cell data)
// 4. Call ckb-blst verification APIs
```

**Library API Categories**:

| API Category | Functions | CKB Data Source |
|-------------|-----------|-----------------|
| Key Generation | `SecretKey::key_gen()`, `sk_to_pk()` | N/A (off-chain) |
| Signing | `SecretKey::sign()` | N/A (off-chain) |
| Single Verify | `Signature::verify()` | `load_witness` → sig, `load_script`/`load_cell_data` → pk, tx_hash → msg |
| Aggregate Verify | `Signature::aggregate_verify()` | `load_witness` → agg_sig, `load_cell_data` → pks[], msgs[] |
| Fast Agg Verify | `Signature::fast_aggregate_verify()` | `load_witness` → agg_sig, `GroupInput`/`GroupOutput` → pks[] |
| Pre-Aggregated Verify | `fast_aggregate_verify_pre_aggregated()` | `load_cell_data` → pre_agg_pk, `load_witness` → sig |
| Multi-Agg Verify | `verify_multiple_aggregate_signatures()` | Multiple sources for pks[], sigs[], msgs[] |
| Serialization | `compress()`, `serialize()`, `from_bytes()` | Encoding/decoding for on-chain storage |
| Key Aggregation | `AggregatePublicKey::aggregate()` | Combining multiple PKs |
| Sig Aggregation | `AggregateSignature::aggregate()` | Combining multiple signatures |

### 2.3 Possible Contract API Analysis Forms

Per the SKILL framework, this library supports:

- **Witness-driven**: Signatures loaded from `load_witness` carry BLS proofs for authorization
- **Cell data-driven**: Public keys and aggregated keys stored in cell data
- **Script args-driven**: Public key hash in `lock_args` for ownership verification
- **Group aggregation**: Iterate `GroupInput`/`GroupOutput` to collect all PKs for aggregate verify
- **CellDeps-driven**: BLS code deployed as CellDep; config cells may hold trusted PKs
- **Transaction-wide**: `load_tx_hash` provides the message to sign/verify

---

## 3. Test Case Design

### 3.1 BLS Lock Script Scenarios

A BLS Lock script verifies a BLS signature in the witness against the public key in `lock_args`.

| Inputs | Outputs | Scenario | Description |
|--------|---------|----------|-------------|
| `[Cell{lock=BLS_PK}]` | `[]` | Lock single input (burn) | Verify single BLS signature in witness against PK in lock_args. |
| `[Cell{lock=BLS_PK}..Cell{lock=BLS_PK}]` | `[]` | Lock multi-input (grouped) | Group cells by same lock; verify one aggregate signature for the group. |
| `[Cell{lock=BLS_PK}]` | `[Cell{lock=any}]` | Lock single transfer | Standard transfer: verify BLS sig to authorize spending. |
| `[Cell{lock=BLS_PK}..Cell{lock=BLS_PK}]` | `[Cell{lock=any}..Cell{lock=any}]` | Lock multi-transfer | Multiple inputs same lock, aggregate signature verification. |
| `[Cell{lock=BLS_PK_A}, Cell{lock=BLS_PK_B}]` | `[Cell{lock=any}]` | Lock multi-group | Different BLS locks in one TX; each group verified separately. |

### 3.2 BLS Type Script Scenarios

A BLS Type script could enforce that data transitions are authorized by a BLS committee.

| Inputs | Outputs | Scenario | Description |
|--------|---------|----------|-------------|
| `[]` | `[Cell{type=BLS}]` | Mint (creation) | Create new cell; verify admin BLS signature authorizes creation. |
| `[]` | `[Cell{type=BLS}..Cell{type=BLS}]` | Batch mint | Multiple outputs with same type; batch authorization. |
| `[Cell{type=BLS}]` | `[]` | Burn (destroy) | Destroy cell; verify BLS signature authorizes destruction. |
| `[Cell{type=BLS}]` | `[Cell{type=BLS}]` | Transfer (1-to-1) | Data transition; verify BLS committee signature on new data. |
| `[Cell{type=BLS}]` | `[Cell{type=BLS}..Cell{type=BLS}]` | Split (1-to-N) | Split data across outputs; verify aggregate authorization. |
| `[Cell{type=BLS}..Cell{type=BLS}]` | `[Cell{type=BLS}]` | Merge (N-to-1) | Merge inputs; verify aggregate sig + data consistency. |
| `[Cell{type=BLS}..Cell{type=BLS}]` | `[Cell{type=BLS}..Cell{type=BLS}]` | N-to-N transform | Complex multi-input/output; verify committee BLS multi-sig. |

### 3.3 BLS Cryptographic Operation Test Cases

| Operation | Input | Expected | Description |
|-----------|-------|----------|-------------|
| `key_gen` | 32-byte IKM | Valid SK | Deterministic key generation from sufficient entropy. |
| `key_gen` | 31-byte IKM | `BLST_BAD_ENCODING` | Reject insufficient IKM length. |
| `key_gen` | 32-byte zeros | Valid SK (non-zero) | Edge case: all-zero IKM still produces valid key. |
| `sk_to_pk` | Valid SK | Valid PK on G1/G2 | Derive public key from secret key. |
| `sign` | Valid SK + msg + DST | Valid Signature | Sign message with correct domain separation. |
| `verify` | Valid (sig, msg, pk) | `BLST_SUCCESS` | Happy path single signature verification. |
| `verify` | Wrong PK | `BLST_VERIFY_FAIL` | Signature doesn't match public key. |
| `verify` | Wrong msg | `BLST_VERIFY_FAIL` | Signature doesn't match message. |
| `verify` | Wrong DST | `BLST_VERIFY_FAIL` | Wrong domain separation tag. |
| `verify` | Infinity PK | `BLST_PK_IS_INFINITY` | Reject point-at-infinity public key. |
| `verify` | PK not in group | `BLST_POINT_NOT_IN_GROUP` | Reject invalid curve point. |
| `aggregate_verify` | N valid (sig_i, msg_i, pk_i) | `BLST_SUCCESS` | Aggregate verification with unique messages. |
| `aggregate_verify` | Mismatched pk/msg count | `BLST_VERIFY_FAIL` | Input array length mismatch. |
| `aggregate_verify` | Empty inputs | `BLST_VERIFY_FAIL` | Zero-length arrays. |
| `fast_aggregate_verify` | N pks, same msg, agg_sig | `BLST_SUCCESS` | Fast path for same-message aggregate. |
| `fast_aggregate_verify` | Wrong agg_sig | `BLST_VERIFY_FAIL` | Aggregated signature doesn't match. |
| `AggregatePublicKey::aggregate` | 0 PKs | `BLST_AGGR_TYPE_MISMATCH` | Empty PK list. |
| `AggregateSignature::aggregate` | 0 sigs | `BLST_AGGR_TYPE_MISMATCH` | Empty sig list. |
| `PublicKey::deserialize` | Valid compressed bytes | `Ok(PK)` | Deserialize 48-byte compressed PK (min_pk). |
| `PublicKey::deserialize` | Invalid bytes | `Err(BLST_BAD_ENCODING)` | Reject malformed encoding. |
| `PublicKey::deserialize` | Wrong length | `Err(BLST_BAD_ENCODING)` | Reject wrong-length input. |
| `Signature::deserialize` | Valid compressed bytes | `Ok(Sig)` | Deserialize 96-byte compressed sig (min_pk). |
| `Signature::deserialize` | Point not on curve | `Err(BLST_POINT_NOT_ON_CURVE)` | Reject point not on curve. |
| `SecretKey::deserialize` | Valid 32-byte SK | `Ok(SK)` | Deserialize secret key. |
| `SecretKey::deserialize` | Wrong length | `Err(BLST_BAD_ENCODING)` | Reject wrong-length SK. |
| `SecretKey::deserialize` | SK ≥ r (group order) | `Err(BLST_BAD_ENCODING)` | Reject out-of-range SK. |
| `verify_multiple_aggregate_signatures` | Valid multi-sig inputs | `BLST_SUCCESS` | Batch verification with random scalars. |
| `Pairing` | Mixed G1/G2 types | `BLST_AGGR_TYPE_MISMATCH` | Reject mixing min_pk and min_sig. |

---

## 4. CKB-VM Specific Analysis

### 4.1 Cycle Consumption

The CKB-VM has a ~1,000M cycle limit per transaction. The example contract measures BLS operation costs:

| Operation | Estimated Cycles | Notes |
|-----------|-----------------|-------|
| `fast_aggregate_verify` (8 sigs) | ~100-200M | Pairing computation dominates |
| `fast_aggregate_verify` (16 sigs) | ~150-300M | Linear scaling with aggregation count |
| `fast_aggregate_verify` (32 sigs) | ~200-400M | Approaches practical limits |
| `fast_aggregate_verify` (64 sigs) | ~300-600M | May approach cycle cap |
| `fast_aggregate_verify` (128 sigs) | ~500-900M | Near cycle limit; may fail on mainnet |
| `fast_aggregate_verify_pre_aggregated` | ~80-150M | Cheaper: PK already aggregated off-chain |
| Single `verify` | ~50-100M | Single pairing check |

**Recommendation**: For on-chain verification, prefer `fast_aggregate_verify_pre_aggregated` with pre-aggregated public keys stored in CellDeps. This minimizes on-chain cycle consumption.

### 4.2 Memory Model Concerns

| Issue | Risk | Description |
|-------|------|-------------|
| `alloca()` usage | HIGH | Stack allocation with input-dependent sizes in C core (`keygen.c:92`, `hash_to_field.c:125`, `pairing.c:224-225`, `multi_scalar.c:142/185`). CKB-VM has limited stack; large inputs cause overflow. |
| VLA usage | MEDIUM | C99 Variable Length Arrays in `keygen.c:94`, `hash_to_field.c:127`. Same stack overflow risk. |
| `Box<[u64]>` allocation | LOW | Rust `Pairing` struct heap-allocates via `alloc`. CKB-VM supports this via `ckb_std::default_alloc!()`. |
| Alignment | LOW | `Pairing` casts `Box<[u64]>` to `*mut blst_pairing`. u64 provides 8-byte alignment which should suffice for RISC-V. |

### 4.3 Build System (CKB-VM Path)

The `build.rs` conditionally compiles for CKB-VM when `feature = "ckb-vm"`:

```
Defines: BUILD_FOR_CKB_VM, USE_MUL_MONT_384_ASM, CKB_DECLARATION_ONLY
Includes: deps/ckb-c-stdlib, deps/ckb-c-stdlib/libc
Flags: -nostdinc -nostdlib -nostartfiles -fPIC -O3
Assembly: blst_mul_mont_384.riscv.S, blst_mul_mont_384x.riscv.S
```

**Issues Found**:
1. **Compiler fallback bug** (`build.rs:98-109`): Loop tries compilers but doesn't `break` on success; may override correct compiler.
2. **Trailing space in define** (`build.rs:114`): `.define("CKB_DECLARATION_ONLY ", None)` has trailing space — may cause preprocessing issues.

---

## 5. Security Findings

### 5.1 HIGH Severity

| ID | File | Line(s) | Finding |
|----|------|---------|---------|
| H-1 | `bindings/rust/src/lib.rs` | 720 | **Undefined Behavior**: `ptr::null::<$sig_aff>().as_ref()` creates a reference from null pointer — instant UB in Rust. Should use `Option<&T>` pattern. |
| H-2 | `bindings/rust/src/lib.rs` | 691-695, 706-712, 811-850 | **Transmute lifetime erasure**: `transmute::<*const &T, usize>` and back erases lifetime info, bypassing borrow checker. Unnecessary in single-threaded CKB-VM context. |
| H-3 | `src/keygen.c`, `src/hash_to_field.c`, `src/pairing.c`, `src/multi_scalar.c`, `src/bulk_addition.c`, `src/ec_mult.h` | Various | **Unchecked `alloca()`**: Stack allocation with input-dependent sizes. On CKB-VM's limited stack, attacker-controlled inputs cause stack overflow / crash. |

### 5.2 MEDIUM Severity

| ID | File | Line(s) | Finding |
|----|------|---------|---------|
| M-1 | `src/keygen.c` | 92, 94 | **VLA with unchecked size**: `info_prime[info_len + 2 + 1]` with unbounded `info_len`. |
| M-2 | `src/aggregate.c` | 73-74, 79-80 | **Magic sentinel `(void *)42`**: DST pointer stored as magic value. Fragile on CKB-VM's 64-bit address space. |
| M-3 | `bindings/rust/src/lib.rs` | 58-87 | **Alignment assumptions**: `Pairing` casts `Box<[u64]>` to `*mut blst_pairing`. Relies on C struct having ≤8-byte alignment. |
| M-4 | `bindings/rust/src/lib.rs` | 687, 807 | **Missing message uniqueness**: `aggregate_verify` has `// TODO - check msg uniqueness?` — BLS spec requires unique messages to prevent rogue key attacks. |
| M-5 | `bindings/rust/src/lib.rs` | 139, 199, 219 | **`panic!("whaaaa?")` in public API**: Type downcast failure causes unrecoverable panic in CKB-VM (wastes all cycles). |
| M-6 | `.github/workflows/` | Various | **Outdated CI Actions**: `actions/checkout@v2`, `actions/cache@v2`, `github/codeql-action@v1` (deprecated). |
| M-7 | `bindings/rust/build.rs` | 114 | **Trailing space in define**: `"CKB_DECLARATION_ONLY "` has trailing space. |

### 5.3 LOW Severity

| ID | File | Line(s) | Finding |
|----|------|---------|---------|
| L-1 | `build.sh` | 44 | **`eval` on CLI args**: `eval "$1"` allows command injection from build arguments. |
| L-2 | `bindings/rust/build.rs` | 98-109 | **Missing `break` in compiler loop**: May override correct compiler with later candidate. |
| L-3 | `src/keygen.c` | 134-137 | **Silent zero SK**: `blst_keygen` returns zeroed key for short IKM without error. Rust wrapper catches this, but C callers may not. |
| L-4 | `bindings/rust/src/lib.rs` | 57-60 | **No `Send`/`Sync`**: `Pairing` struct has neither explicit `Send` nor `!Send`. |
| L-5 | `bindings/rust/src/lib.rs` | 386-392 | **Unzeroized serialized SK**: `SecretKey::serialize()` returns `[u8;32]` by value; not zeroized on drop. |
| L-6 | `.github/workflows/ckb.yml` | 40-44 | **No checksum on downloaded binary**: `ckb-debugger` downloaded without SHA verification. |
| L-7 | `bindings/rust/src/lib.rs` | 1315-1321 | **`MaybeUninit::assume_init`**: Test code uses `assume_init` after FFI call — fragile pattern. |
| L-8 | `bindings/rust-examples/ckb/rust-toolchain.toml` | 1-2 | **Pinned nightly**: `nightly-2023-04-22` is very old; may miss compiler bug fixes. |

---

## 6. Error Scenarios and Return Codes

| Code | Value | Cause | How to Trigger | Expected Behavior | CKB-VM Impact |
|------|-------|-------|----------------|-------------------|---------------|
| `BLST_SUCCESS` | 0 | Operation succeeded | Valid inputs | Return 0 | Script passes |
| `BLST_BAD_ENCODING` | 1 | Invalid serialization | Malformed PK/Sig bytes in witness/data | Return error | Script fails (non-zero exit) |
| `BLST_POINT_NOT_ON_CURVE` | 2 | Deserialized point not on BLS12-381 | Random bytes as PK/Sig | Return error | Script fails |
| `BLST_POINT_NOT_IN_GROUP` | 3 | Point on curve but not in correct subgroup | Crafted point bypassing curve check | Return error | Script fails |
| `BLST_AGGR_TYPE_MISMATCH` | 4 | Mixed G1/G2 in aggregation, or empty input | Empty PK/Sig array, or mixing min_pk with min_sig | Return error | Script fails |
| `BLST_VERIFY_FAIL` | 5 | Signature verification failed | Wrong sig, wrong pk, wrong msg, wrong DST | Return error | Script fails |
| `BLST_PK_IS_INFINITY` | 6 | Public key is point at infinity | All-zero PK bytes | Return error | Script fails |
| `panic!` | N/A | Type downcast failure in `Pairing::aggregate/mul_n_aggregate/aggregated` | Pass wrong type via `&dyn Any` | **Unrecoverable crash** | **Wastes all cycles, script fails** |
| Stack overflow | N/A | `alloca`/VLA with huge input | Very large `info_len`, `nelems`, or `npoints` | **Crash** | **CKB-VM abort, script fails** |

---

## 7. CKB Grouping Logic Analysis

### 7.1 Lock Script Grouping

When used as a Lock script, cells with the same `Hash(LockScript)` are grouped:

```
Group = Hash(code_hash || hash_type || args)
```

For BLS, `args` would contain the BLS public key (48 bytes for min_pk, 96 bytes for min_sig). All cells in the same group share the same BLS public key and are verified together:

- **Single group execution**: The Lock script runs once per group, verifying one signature from the first witness against the group's public key.
- **Signature in witness**: The BLS signature should be in the witness at the group's first input index.
- **Multi-cell authorization**: One aggregate signature can authorize spending all cells in the group.

### 7.2 Type Script Grouping

For Type scripts, both input and output cells are grouped:

- **Input validation**: Verify BLS signature authorizes the state transition.
- **Output validation**: Verify new cell data conforms to rules (e.g., committee-signed state).
- **Cross-group consistency**: Use `Source::GroupInput` and `Source::GroupOutput` to iterate within the group.

---

## 8. Testing Considerations for CKB Deployment

### 8.1 Coverage Gaps in Current Tests

| Area | Current Coverage | Gap |
|------|-----------------|-----|
| Single sign/verify | ✅ `test_sign` | None |
| Aggregate verify | ✅ `test_aggregate` | Missing: duplicate message test |
| Multiple agg sigs | ✅ `test_multiple_agg_sigs` | Missing: large batch (>100 sigs) |
| Serialization roundtrip | ✅ `test_serialization` | Missing: malformed input edge cases |
| CKB-VM execution | ✅ CI runs on `riscv64imac` | Missing: cycle profiling, stack limit tests |
| Fuzzing | ❌ None | **Critical gap**: No fuzz testing for deserialization or verification |
| Cross-target consistency | ❌ None | No x86 vs RISC-V result comparison tests |
| Error paths | ⚠️ Partial | Missing: explicit tests for each `BLST_ERROR` variant |
| Infinity/zero edge cases | ⚠️ Partial | Missing: all-zero inputs, point-at-infinity inputs |
| Message uniqueness | ❌ Not enforced | `uniq()` function exists but never called in verify paths |
| Stack overflow | ❌ None | No tests for `alloca` with large inputs on CKB-VM |

### 8.2 Recommended Test Matrix

| Inputs | Outputs | Scenario | Description | Priority |
|--------|---------|----------|-------------|----------|
| `[BlsCell]` | `[]` | Lock single burn | Verify BLS sig in witness authorizes cell destruction. | P0 |
| `[BlsCell, BlsCell]` | `[]` | Lock grouped burn | Aggregate sig verification for grouped cells. | P0 |
| `[BlsCell]` | `[Cell]` | Lock transfer | Standard transfer with BLS authorization. | P0 |
| `[BlsCell..BlsCell]` | `[Cell..Cell]` | Lock multi-transfer | Multiple grouped inputs, one agg sig. | P1 |
| `[]` | `[TypedCell]` | Type: mint | Committee BLS sig authorizes creation. | P0 |
| `[TypedCell]` | `[]` | Type: burn | Committee BLS sig authorizes destruction. | P1 |
| `[TypedCell]` | `[TypedCell]` | Type: 1-to-1 transform | State transition with BLS committee approval. | P0 |
| `[TypedCell..TypedCell]` | `[TypedCell..TypedCell]` | Type: N-to-N | Complex state transition. | P2 |
| `[BlsCell]` | `[]` | Invalid sig | Wrong BLS signature in witness → script fails. | P0 |
| `[BlsCell]` | `[]` | Invalid pk | Malformed public key bytes → deserialization error. | P0 |
| `[BlsCell]` | `[]` | Infinity pk | All-zero PK → `BLST_PK_IS_INFINITY`. | P1 |
| `[BlsCell]` | `[]` | Missing witness | No witness data → deserialization error or panic. | P0 |
| `[BlsCell..BlsCell]` | `[]` | Duplicate messages | Same message signed by different keys → potential attack. | P0 |
| `[BlsCell]` | `[]` | Cycle limit | 128+ signatures → may exceed ~1000M cycles. | P1 |
| `[BlsCell]` | `[]` | Stack overflow | Crafted inputs triggering large `alloca` → crash. | P1 |
| `[BlsCell]` | `[]` | Cross-target verify | Same inputs produce same result on x86 and RISC-V. | P1 |

---

## 9. Upstream Version Gap Analysis

This repository is forked from `supranational/blst`. Key observations:

- The RISC-V assembly files (`blst_mul_mont_384.riscv.S`, `blst_mul_mont_384x.riscv.S`) are **custom additions** not present in upstream blst.
- The `BUILD_FOR_CKB_VM` preprocessor path in `vect.h` is a custom modification.
- The CKB-specific `build.rs` logic (compiler detection, CKB flags) is unique to this fork.
- **Risk**: Upstream blst may have received security patches not present in this fork. A version gap analysis is needed.

---

## 10. TODO: Further Review Required

- [ ] **RISC-V Assembly Audit**: `blst_mul_mont_384.riscv.S` and `blst_mul_mont_384x.riscv.S` implement Montgomery multiplication — correctness is critical for all cryptographic operations. Needs expert assembly review for:
  - Register usage and calling conventions (RISC-V ABI compliance)
  - Edge cases: zero, max-field-element, boundary values
  - Constant-time behavior (no data-dependent branches)

- [ ] **Side-Channel Analysis**: Verify constant-time properties of:
  - `mul_mont_n()` in `no_asm.h` (pure-C fallback for CKB-VM when `__BLST_NO_ASM__` is set but assembly is also linked)
  - `POINTonE1_mult_w5` / `POINTonE2_mult_w5` scalar multiplication
  - `vec_select()`, `cneg_fp()`, `is_zero()` helper functions

- [ ] **CKB-VM Stack Size Testing**: Determine actual stack usage under worst-case inputs and compare against CKB-VM stack limits. Particularly:
  - `alloca()` in `hash_to_field.c` with large `nelems`
  - `alloca()` in `pairing.c` (Miller loop temporaries)
  - Recursive/deep call chains in `multi_scalar.c`

- [ ] **Upstream Sync**: Compare against latest `supranational/blst` release for missing security patches.

- [ ] **Fuzz Testing**: Implement fuzzers for:
  - `PublicKey::deserialize()` / `Signature::deserialize()`
  - `Signature::verify()` with random inputs
  - `AggregateSignature::aggregate()` with malformed signatures

- [ ] **RFC 9380 Test Vectors**: Verify `expand_message_xmd` implementation against standard hash-to-curve test vectors.

- [ ] **Integer Overflow in Size Calculations**: Review `blst_pairing_sizeof() / 8` and `blst_uniq_sizeof(n_elems) / 8` for potential truncation/overflow.

- [ ] **`no_std` Allocator Compatibility**: Verify `default_alloc!()` from `ckb-std` handles OOM gracefully for large `Vec` allocations in the library.

- [ ] **`__int128` on RISC-V**: The `no_asm.h` uses `unsigned __int128` which requires compiler support on RISC-V. Verify the cross-compiler supports this.

- [ ] **Pairing Merge Safety**: `blst_pairing_merge` with `AGGR_UNDEFINED` does `vec_copy(ctx, ctx1, sizeof(*ctx))` — verify DST pointer doesn't become dangling.

---

## 11. Summary

| Category | Count | Critical Items |
|----------|-------|----------------|
| HIGH Severity | 3 | Null-ptr UB (H-1), transmute abuse (H-2), unchecked alloca (H-3) |
| MEDIUM Severity | 7 | Missing msg uniqueness (M-4), panic in API (M-5), VLA overflow (M-1) |
| LOW Severity | 8 | Eval injection (L-1), compiler bug (L-2), unzeroized SK (L-5) |
| Test Gaps | 11 | Fuzzing, cross-target, stack overflow, error paths, cycle limits |
| TODO Items | 10 | Assembly audit, side-channel, upstream sync, fuzz testing |

### Overall Risk Assessment

The core cryptographic C code is from the reputable `blst` library and is generally well-written. The primary security concerns are:

1. **CKB-VM integration layer** (Rust FFI bindings): Contains UB, unsafe transmute patterns, and panicking code paths that are particularly dangerous in the constrained CKB-VM environment.

2. **Stack safety on CKB-VM**: Multiple `alloca()`/VLA usages with input-dependent sizes are the highest operational risk for on-chain deployment.

3. **Missing cryptographic safeguards**: Message uniqueness enforcement is absent, which could enable signature forgery under specific conditions.

4. **Custom RISC-V assembly**: Not present in upstream blst; requires independent cryptographic correctness review.

**Recommendation**: Before deploying in production CKB contracts, address H-1 through H-3, implement message uniqueness checks (M-4), replace panics with error returns (M-5), and commission an independent audit of the RISC-V assembly code.
