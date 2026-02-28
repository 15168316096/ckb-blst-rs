# Security Audit Report: ckb-blst-rs

**Date**: 2026-02-28  
**Scope**: Full repository code review of `ckb-blst-rs` (BLS12-381 cryptographic library with CKB-VM compatibility)  
**Auditor**: Automated Security Review  

---

## Executive Summary

This repository is a fork/adaptation of the [blst](https://github.com/supranational/blst) BLS12-381 cryptographic library, with added support for CKB-VM (RISC-V target). The codebase consists of:

- **C core**: BLS12-381 curve operations, pairing, hashing, key generation, SHA-256
- **Rust bindings**: FFI wrappers and high-level BLS signature API
- **Build system**: Custom build.rs with CKB-VM cross-compilation support
- **Assembly**: Platform-specific optimized assembly (x86_64, ARM, RISC-V)

---

## Findings

### HIGH Severity

#### H-1: Undefined Behavior via Null Pointer Dereference in `aggregate_verify`
**File**: `bindings/rust/src/lib.rs`, line 720  
**Code**:
```rust
&unsafe { ptr::null::<$sig_aff>().as_ref() },
```
**Description**: `ptr::null::<T>().as_ref()` creates a reference from a null pointer, which is **instant undefined behavior** in Rust regardless of whether the reference is ever dereferenced. The Rust reference guarantees that references are never null. While this is intentionally passing `None` (since `as_ref()` on a null raw pointer returns `None` for `Option<&T>`), creating a null reference directly is UB per the Rust language spec.  
**Impact**: Compiler may optimize based on the assumption that references are non-null, potentially leading to unpredictable behavior.  
**Recommendation**: Replace with `&None::<$sig_aff>` or restructure to pass `Option<&$sig_aff>` directly as `None`.

#### H-2: Extensive use of `mem::transmute` for lifetime erasure
**File**: `bindings/rust/src/lib.rs`, lines 691-695, 706-712, 811-850  
**Description**: The `aggregate_verify` and `verify_multiple_aggregate_signatures` functions use `transmute` to convert pointers to `usize` and back. The comment says "Bypass 'lifetime limitations by brute force." While tagged as safe because threads are joined (though no actual threading exists in this no-std version), this pattern:
1. Erases all lifetime information, bypassing the borrow checker
2. Could cause use-after-free if the code is ever refactored
3. Is unnecessary in the current single-threaded implementation  
**Impact**: Memory safety guarantees are lost in these code paths.  
**Recommendation**: Remove the transmute-based lifetime erasure since no threading is used. Directly pass the slices.

#### H-3: Stack-based `alloca` with user-influenced sizes
**File**: `src/keygen.c` line 92, `src/hash_to_field.c` line 125, `src/pairing.c` lines 224-225, `src/multi_scalar.c` lines 142/185, `src/bulk_addition.c` line 149, `src/ec_mult.h` line 107  
**Description**: Multiple uses of `alloca()` with sizes derived from input parameters (e.g., `info_len`, `nelems`, `npoints`, `n`). Stack overflow is possible if an attacker can control these sizes.  
**Impact**: Stack overflow leading to crash or potential code execution.  
**Recommendation**: Add bounds checking before `alloca()` calls, or switch to heap allocation with size limits.

### MEDIUM Severity

#### M-1: VLA (Variable Length Arrays) with unchecked sizes
**File**: `src/keygen.c` line 94, `src/hash_to_field.c` line 127  
**Code**:
```c
unsigned char info_prime[info_len + 2 + 1];  // keygen.c:94
limb_t pseudo_random[len_in_bytes/sizeof(limb_t)];  // hash_to_field.c:127
```
**Description**: C99 VLAs are used with sizes derived from function parameters. If `info_len` or `nelems` are large, this can overflow the stack.  
**Impact**: Stack overflow / denial of service.  
**Recommendation**: Validate input sizes or use heap allocation.

#### M-2: Pairing context uses magic sentinel value `(void *)42`
**File**: `src/aggregate.c` lines 73-74, 79-80  
**Description**: The DST pointer is stored as magic value `42` when DST is placed immediately after the PAIRING struct in memory. This is a fragile sentinel pattern — any pointer that happens to equal `42` would be misinterpreted.  
**Impact**: Low probability of collision on 64-bit systems, but this is a code smell that could cause issues on embedded/CKB-VM with smaller address spaces.  
**Recommendation**: Use a separate flag field instead of a sentinel pointer value.

#### M-3: `Pairing` struct casts `Box<[u64]>` to `*mut blst_pairing`
**File**: `bindings/rust/src/lib.rs`, lines 58-87  
**Description**: The `Pairing` struct allocates a `Vec<u64>` sized by `blst_pairing_sizeof() / 8` and casts it to `*mut blst_pairing`. This relies on:
1. Correct alignment (u64 provides 8-byte alignment, which may not match C struct alignment requirements)
2. Correct size calculation (integer division truncation if `blst_pairing_sizeof()` is not 8-aligned, though the C code ensures 8-byte alignment)  
**Impact**: Potential alignment issues on some platforms.  
**Recommendation**: Verify alignment requirements or use `std::alloc::Layout` for proper allocation.

#### M-4: No message uniqueness check in `aggregate_verify`
**File**: `bindings/rust/src/lib.rs`, lines 687 and 807  
**Code**: `// TODO - check msg uniqueness?`  
**Description**: The BLS signature specification requires that messages must be unique in aggregate verification to prevent rogue key attacks. The code has TODO comments but does not enforce uniqueness.  
**Impact**: If duplicate messages are passed, the aggregate verification may be vulnerable to certain cryptographic attacks.  
**Recommendation**: Enforce message uniqueness using the existing `uniq()` function.

#### M-5: `panic!("whaaaa?")` in production code paths
**File**: `bindings/rust/src/lib.rs`, lines 139, 199, 219  
**Description**: The `aggregate`, `mul_n_aggregate`, and `aggregated` methods panic with an uninformative message when type downcasting fails. These are public API methods that accept `&dyn Any`.  
**Impact**: Unrecoverable crash in production. Using `&dyn Any` is an unusual pattern that makes type errors hard to detect at compile time.  
**Recommendation**: Return `Result<_, BLST_ERROR>` instead of panicking, or use generic type parameters for compile-time type safety.

#### M-6: Outdated GitHub Actions versions
**File**: `.github/workflows/ci.yml`, `.github/workflows/codeql-analysis.yml`  
**Description**:
- `actions/checkout@v2` and `@v3` (current is v4)
- `actions/cache@v2` (current is v4)
- `actions/setup-java@v1` (current is v4)
- `actions/setup-node@v1` (current is v4)
- `github/codeql-action/init@v1` and `github/codeql-action/analyze@v1` (current is v3, **v1 is deprecated and no longer receives security updates**)  
**Impact**: Missing security patches for CI/CD pipeline, potential supply chain risks.  
**Recommendation**: Update all Actions to their latest major versions.

### LOW Severity

#### L-1: `build.sh` uses `eval` on command-line arguments
**File**: `build.sh` line 44  
**Code**: `*=*)    eval "$1";;`  
**Description**: The build script evaluates arbitrary `key=value` arguments using shell `eval`. This can execute arbitrary commands if user-controlled input is passed.  
**Impact**: Local code execution if an attacker can influence build script arguments.  
**Recommendation**: Use variable assignment without `eval` or validate input format.

#### L-2: CKB-VM build tries multiple compilers without strict ordering
**File**: `bindings/rust/build.rs` lines 97-109  
**Description**: When `CC_riscv64imac_unknown_none_elf` is not set, the build script tries multiple compilers (`riscv64-unknown-elf-gcc`, `riscv64-elf-gcc`, `riscv64-none-elf-gcc`) but doesn't `break` on success — it may override a successfully found compiler with a later one.  
**Impact**: Wrong compiler may be selected.  
**Recommendation**: Add `break` after successful compiler detection.

#### L-3: `blst_keygen` returns zeroed SK on short IKM without error
**File**: `src/keygen.c` lines 134-137  
**Code**:
```c
if (IKM_len < 32) {
    vec_zero(SK, sizeof(pow256));
    return;
}
```
**Description**: If `IKM_len < 32`, the function silently returns a zeroed (invalid) secret key without signaling an error. The Rust wrapper in `lib.rs:319-322` does check `ikm.len() < 32` and returns an error, but direct C callers may not be aware.  
**Impact**: C callers could silently get a zero secret key.  
**Recommendation**: Document this behavior clearly or return an error code.

#### L-4: No `Send`/`Sync` implementation for `Pairing`
**File**: `bindings/rust/src/lib.rs`, lines 57-60  
**Description**: The `Pairing` struct contains `Box<[u64]>` which is `Send + Sync`, but the internal mutable pointer cast pattern makes thread safety questionable. The struct is neither explicitly `Send` nor explicitly `!Send`.  
**Impact**: If used across threads (the code comments mention multi-threading patterns), data races are possible.  
**Recommendation**: Explicitly implement or deny `Send`/`Sync` with appropriate safety documentation.

#### L-5: Test uses `MaybeUninit::assume_init` on scalar
**File**: `bindings/rust/src/lib.rs`, line 1321  
**Description**: Test code creates `MaybeUninit::<blst_scalar>` and assumes it's initialized after `blst_scalar_from_uint64`. While the C function does fully initialize the struct, this pattern is fragile.  
**Impact**: Test-only; no production impact.

#### L-6: `SecretKey` serialized bytes not zeroized
**File**: `bindings/rust/src/lib.rs`, lines 386-392  
**Description**: `SecretKey::serialize()` returns `[u8; 32]` by value. This array on the stack is not zeroized when it goes out of scope. While `SecretKey` itself derives `Zeroize(drop)`, the serialized copy does not.  
**Impact**: Secret key material may remain in stack memory after use.  
**Recommendation**: Use a `Zeroizing<[u8; 32]>` wrapper from the zeroize crate, or document that the caller is responsible for scrubbing.

#### L-7: `ckb-debugger` downloaded over HTTPS without checksum verification
**File**: `.github/workflows/ckb.yml` lines 40-44  
**Description**: The CI downloads `ckb-debugger` binary from GitHub releases without verifying a SHA checksum.  
**Impact**: Supply chain attack vector if the release is compromised.  
**Recommendation**: Pin to a specific version with SHA256 checksum verification.

---

## Informational

#### I-1: Large amount of `unsafe` code (71 unsafe blocks in lib.rs)
The Rust binding layer contains extensive `unsafe` code for FFI. This is expected for a crypto library wrapper but increases the attack surface.

#### I-2: `core::ptr::null()` usage in bindgen tests
The auto-generated `bindings.rs` uses `core::ptr::null::<Type>()` in offset tests, which is deprecated/UB. This is a known bindgen issue.

#### I-3: The `no_asm.h` pure-C fallback uses `unsigned __int128`
This is a compiler extension (GCC/Clang) and not standard C. On RISC-V with `__BLST_NO_ASM__` defined, this needs the toolchain to support 128-bit integers.

#### I-4: `N_MAX` is hardcoded to 8
The pairing batch size limit (`N_MAX = 8`) means that for more than 8 signatures being aggregated, multiple miller loops are performed and multiplied together. This is a performance choice, not a security issue.

---

## TODO: Areas Requiring Further Review

- [ ] **RISC-V Assembly Correctness**: The RISC-V assembly files (`blst_mul_mont_384.riscv.S`, `blst_mul_mont_384x.riscv.S`) are critical for CKB-VM correctness. They need manual expert review for:
  - Correctness of Montgomery multiplication
  - Register usage and calling conventions
  - Edge cases (zero inputs, max-value inputs)
  
- [ ] **Side-channel Analysis**: The C code uses constant-time patterns (e.g., `vec_select`, `cneg_fp`), but a thorough timing/power analysis should verify:
  - `mul_mont_n` in `no_asm.h` for constant-time behavior on RISC-V
  - `POINTonE1_mult_w5` / `POINTonE2_mult_w5` scalar multiplication windowing
  - Branch-free behavior of `is_zero()`, `vec_is_equal()`, `vec_select()`
  
- [ ] **CKB-VM Memory Model Compatibility**: Verify that the CKB-VM execution environment properly handles:
  - Stack size limits (given the `alloca` usage)
  - Memory alignment requirements for 64-bit operations
  - The `BUILD_FOR_CKB_VM` preprocessor paths
  
- [ ] **Upstream blst Version Tracking**: Determine which version of upstream `blst` this is forked from and check for any security patches that may be missing. The upstream repo has had multiple security-relevant commits.

- [ ] **Fuzzing**: No fuzzing infrastructure exists. Recommend adding:
  - Deserialization fuzzing (PublicKey, Signature from_bytes)
  - Verification fuzzing (aggregate_verify with random inputs)
  - Cross-target verification (x86_64 vs RISC-V result comparison)

- [ ] **`expand_message_xmd` Implementation**: The hash-to-curve implementation should be verified against the [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380) test vectors.

- [ ] **`blst_pairing_merge` Safety**: The merge function copies entire context with `vec_copy(ctx, ctx1, sizeof(*ctx))` when `AGGR_UNDEFINED`. Verify this doesn't create dangling DST pointers.

- [ ] **Integer Overflow in Size Calculations**: Review `blst_pairing_sizeof()`, `blst_uniq_sizeof()` for potential integer overflow when multiplied by element counts in Rust wrappers (lines 64, 253).

- [ ] **Dependency Audit**: The `zeroize` crate (^1.1) should be checked for known vulnerabilities. Build dependencies `cc` (1.0) and `glob` (0.3) should also be audited.

- [ ] **`no_std` Compatibility Testing**: Verify that all code paths work correctly in `no_std` mode, especially memory allocation patterns and the `alloc` usage.

---

## Security Summary

| Severity | Count |
|----------|-------|
| HIGH     | 3     |
| MEDIUM   | 6     |
| LOW      | 7     |
| INFO     | 4     |

The most critical findings are the undefined behavior from null pointer reference creation (H-1), the transmute-based lifetime erasure (H-2), and the unchecked `alloca` sizes (H-3). The medium-severity findings around missing message uniqueness checks (M-4) and outdated CI actions (M-6) should also be addressed.

Overall, the core cryptographic C code appears to be well-written (it's from the reputable blst library by Supranational). The main concerns are in:
1. The Rust FFI binding layer (unsafe code patterns)
2. The CKB-VM specific code paths (less tested)
3. The CI/CD pipeline security posture
