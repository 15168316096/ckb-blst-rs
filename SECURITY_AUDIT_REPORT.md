# 安全审计报告: ckb-blst-rs

## 1. 执行摘要

| 项目 | 信息 |
|------|------|
| **项目名称** | ckb-blst-rs (BLS12-381 密码学库 CKB-VM 适配版) |
| **仓库** | https://github.com/cryptape/ckb-blst-rs |
| **审计日期** | 2026-03-02 |
| **审计范围** | 全仓库代码审计 (Rust FFI 绑定 + C 密码学核心 + RISC-V 汇编 + 构建系统 + CI/CD) |
| **审计方法论** | AI-Driven Security Audit (security-audit SKILL.md) |
| **语言/技术栈** | Rust 2021 edition (no_std), C99, RISC-V Assembly |
| **项目类型** | 密码学库 (BLS12-381 签名方案) |
| **上游来源** | Fork 自 [supranational/blst](https://github.com/supranational/blst) |
| **目标平台** | CKB-VM (riscv64imac-unknown-none-elf) + x86_64/aarch64 |
| **依赖数** | 3 (zeroize, cc, glob) |
| **源文件数** | 55 |
| **现有测试** | 4 个单元测试 + 1 个 CKB-VM 集成测试 |
| **审计项总数** | 28 |
| **发现问题数** | 12 |

---

## 2. 风险评级

| 级别 | 数量 | 说明 |
|------|------|------|
| ■ Critical | 3 | 未定义行为 (UB)、无界栈分配、VLA 栈溢出 |
| ■ High | 4 | transmute 滥用、消息唯一性缺失、密钥材料泄露、不可恢复 panic |
| ■ Medium | 4 | 签名验证时序、模糊测试缺失、CI 供应链、ASM/no_asm 矛盾 |
| ■ Low | 1 | 编译器查找循环 bug |
| ✅ 通过 | 16 | 反序列化检查、错误码、roundtrip、依赖版本、对齐等 |

---

## 3. 关键发现（按严重级别降序）

### ❌ CRITICAL

---

### AUDIT-MEMORY-003: Rust 空指针引用导致未定义行为 (UB)

| 属性 | 值 |
|------|-----|
| **ID** | AUDIT-MEMORY-003 |
| **严重级别** | 🔴 Critical |
| **影响范围** | aggregate_verify 调用路径 (min_pk + min_sig 模块) |
| **CVSS 参考** | 内存安全 — 未定义行为 |

**描述**:

在 `bindings/rust/src/lib.rs` 第 720 行:

```rust
&unsafe { ptr::null::<$sig_aff>().as_ref() },
```

`ptr::null::<T>().as_ref()` 在 Rust 中创建一个来自空指针的引用。根据 Rust 语言规范，引用永远不能为 null。虽然 `as_ref()` 对空指针返回 `None`（`Option<&T>`），但创建空指针引用本身已构成 **即时未定义行为 (instant UB)**。编译器可能基于"引用不为 null"的假设进行优化，导致不可预测的运行时行为。

**影响**:

所有通过 `aggregate_verify`、`fast_aggregate_verify`、`verify` 路径的签名验证均会触发此 UB。在 CKB-VM 执行环境中，编译器优化可能导致验证逻辑被完全跳过。

**关键代码引用**:

```rust
// bindings/rust/src/lib.rs:717-724
if pairing.aggregate(
    &pks[work].point,
    pks_validate,
    &unsafe { ptr::null::<$sig_aff>().as_ref() },  // ← UB HERE
    false,
    &msgs[work],
    &[],
) != BLST_ERROR::BLST_SUCCESS
```

**修复建议**:

```rust
// 方案 1: 使用 Option<&T> 的 None
let no_sig: Option<&$sig_aff> = None;
if pairing.aggregate(
    &pks[work].point,
    pks_validate,
    &no_sig,
    false,
    &msgs[work],
    &[],
)
```

---

### AUDIT-MEMORY-001: alloca() 分配大小无上限检查

| 属性 | 值 |
|------|-----|
| **ID** | AUDIT-MEMORY-001 |
| **严重级别** | 🔴 Critical |
| **影响范围** | keygen、hash_to_field、pairing、multi_scalar、bulk_addition、ec_mult |
| **CVSS 参考** | 资源耗尽 — 栈溢出 |

**描述**:

C 核心代码中有 **8 处 `alloca()`** 调用，分配大小来自函数参数，无任何上限检查:

| 文件 | 行号 | 大小来源 |
|------|------|---------|
| `src/keygen.c` | 92 | `info_len + 2 + 1` |
| `src/hash_to_field.c` | 125 | `len_in_bytes` (= L × nelems) |
| `src/pairing.c` | 224 | `n * sizeof(POINTonE2)` |
| `src/pairing.c` | 225 | `n * sizeof(POINTonE1_affine)` |
| `src/multi_scalar.c` | 142 | `2 * sizeof(ptype_affine) * npoints * nwin` |
| `src/multi_scalar.c` | 185 | `sizeof(ptype) * scratch_sz` |
| `src/bulk_addition.c` | 149 | `npoints * sizeof(ptype)` |
| `src/ec_mult.h` | 107 | `(1<<(SZ-1)) * sizeof(ptype)` |

**影响**:

在 CKB-VM 中，栈空间极为有限。攻击者若能控制 `nelems`、`npoints`、`n` 等参数的大小，可导致栈溢出，使合约执行崩溃。

**修复建议**:

在每处 `alloca()` 调用前添加大小上限检查：
```c
if (n > MAX_SAFE_ALLOCA_ELEMS) return BLST_BAD_ENCODING;
```
或改为使用堆分配（在 CKB-VM 环境中通过 `alloc` 支持）。

---

### AUDIT-MEMORY-002: C99 VLA 栈溢出风险

| 属性 | 值 |
|------|-----|
| **ID** | AUDIT-MEMORY-002 |
| **严重级别** | 🔴 Critical |
| **影响范围** | keygen、hash_to_field、no_asm Montgomery 乘法 |

**描述**:

3 处 C99 VLA 使用大小来自函数参数:

```c
// src/keygen.c:94
unsigned char info_prime[info_len + 2 + 1];

// src/hash_to_field.c:127
limb_t pseudo_random[len_in_bytes/sizeof(limb_t)];

// src/no_asm.h:23
limb_t mask, borrow, mx, hi, tmp[n+1], carry;
```

**影响**: 与 AUDIT-MEMORY-001 相同，大输入可导致 CKB-VM 栈溢出。

---

### ❌ HIGH

---

### AUDIT-MEMORY-004: transmute 滥用绕过 Rust 借用检查器

| 属性 | 值 |
|------|-----|
| **ID** | AUDIT-MEMORY-004 |
| **严重级别** | 🟠 High |
| **影响范围** | aggregate_verify, verify_multiple_aggregate_signatures |

**描述**:

`lib.rs` 中有 **13 处 `mem::transmute`** 调用，将指针转换为 `usize` 再转回，目的是"绕过生命周期限制"（原代码注释: "Bypass 'lifetime limitations by brute force"）。

```rust
let raw_pks = unsafe {
    transmute::<*const &PublicKey, usize>(pks.as_ptr())
};
// ... 后续重构回指针
let pks = unsafe {
    slice::from_raw_parts(
        transmute::<usize, *const &PublicKey>(raw_pks),
        n_elems,
    )
};
```

在当前 `no_std` 单线程 CKB-VM 环境中，这些 transmute 完全不必要。它们擦除了所有生命周期信息，使得借用检查器无法保证内存安全。若未来代码被重构，可能导致 use-after-free。

**修复建议**: 移除所有 transmute，直接在循环中使用原始切片引用。

---

### AUDIT-CRYPTO-006: 聚合签名验证缺少消息唯一性检查

| 属性 | 值 |
|------|-----|
| **ID** | AUDIT-CRYPTO-006 |
| **严重级别** | 🟠 High |
| **影响范围** | aggregate_verify, verify_multiple_aggregate_signatures |

**描述**:

BLS 签名规范要求聚合验证中的消息必须互不相同，以防止 rogue key 攻击。代码中存在 TODO 注释但未实现:

```rust
// bindings/rust/src/lib.rs:687
// TODO - check msg uniqueness?

// bindings/rust/src/lib.rs:807
// TODO - check msg uniqueness?
```

项目已实现 `uniq()` 函数（lib.rs:244-265），使用基于红黑树的去重，但从未被调用。

**修复建议**:

```rust
if !uniq(msgs) {
    return BLST_ERROR::BLST_VERIFY_FAIL;
}
```

---

### AUDIT-CRYPTO-002: SecretKey 序列化后密钥材料未清零

| 属性 | 值 |
|------|-----|
| **ID** | AUDIT-CRYPTO-002 |
| **严重级别** | 🟠 High |
| **影响范围** | SecretKey::serialize(), SecretKey::to_bytes() |

**描述**:

`SecretKey` 结构体正确使用了 `#[derive(Zeroize)] #[zeroize(drop)]`，但 `serialize()` 方法返回 `[u8; 32]` 值类型:

```rust
pub fn serialize(&self) -> [u8; 32] {
    let mut sk_out = [0; 32];
    unsafe {
        blst_bendian_from_scalar(sk_out.as_mut_ptr(), &self.value);
    }
    sk_out  // ← 返回值在栈上，不受 Zeroize(drop) 保护
}
```

调用者获得的 `[u8;32]` 在离开作用域时不会被清零，密钥材料可能残留在栈内存中。

**修复建议**: 返回 `zeroize::Zeroizing<[u8; 32]>` 包装类型。

---

### AUDIT-MEMORY-006: 公开 API 中的不可恢复 panic

| 属性 | 值 |
|------|-----|
| **ID** | AUDIT-MEMORY-006 |
| **严重级别** | 🟠 High |
| **影响范围** | Pairing::aggregate, Pairing::mul_n_aggregate, Pairing::aggregated |

**描述**:

3 处公开 API 方法使用 `&dyn Any` 参数进行运行时类型检查，类型不匹配时触发 panic:

```rust
// lib.rs:139
} else {
    panic!("whaaaa?")
}
// lib.rs:199 和 lib.rs:219 相同模式
```

在 CKB-VM `no_std` 环境中，panic 导致合约立即中止执行，所有已消耗 cycles 浪费。使用 `&dyn Any` 是不寻常的 API 设计，编译时无法捕获类型错误。

**修复建议**: 返回 `BLST_ERROR::BLST_AGGR_TYPE_MISMATCH` 而非 panic。或使用泛型参数提供编译时类型安全。

---

### ⚠️ MEDIUM

---

### AUDIT-LOGIC-001: sig_groupcheck 在 pairing 计算之后执行

| 属性 | 值 |
|------|-----|
| **ID** | AUDIT-LOGIC-001 |
| **严重级别** | 🟡 Medium |
| **影响范围** | aggregate_verify |

**描述**:

`aggregate_verify` 中，`sig_groupcheck` 验证在所有 pairing 计算完成后才执行 (line 737-742)。这意味着无效签名也会触发完整的 pairing 计算，攻击者可利用此时序执行 DoS 攻击，浪费 CKB-VM cycles。

```rust
// 先执行所有 pairing 计算...
for work in 0..n_workers {
    let mut pairing = Pairing::new($hash_or_encode, dst);
    // ... pairing.aggregate + pairing.commit
}

// 之后才检查 sig 合法性
if sig_groupcheck {
    match self.validate(false) {  // ← line 737, 应该提前
        Err(_err) => return BLST_ERROR::BLST_VERIFY_FAIL,
        _ => (),
    }
}
```

**修复建议**: 将 `sig_groupcheck` 提前到 pairing 循环之前。

---

### AUDIT-SERDE-002: 缺少模糊测试

| 属性 | 值 |
|------|-----|
| **ID** | AUDIT-SERDE-002 |
| **严重级别** | 🟡 Medium |
| **影响范围** | 所有反序列化入口 |

**描述**:

项目无任何模糊测试基础设施。对于处理不可信输入的密码学库，模糊测试是发现内存安全和解析漏洞的关键手段。建议添加:

- `PublicKey::deserialize()` 模糊测试
- `Signature::deserialize()` 模糊测试
- `SecretKey::deserialize()` 模糊测试
- `aggregate_verify` 随机输入模糊测试
- 跨平台 (x86_64 vs riscv64) 结果一致性测试

---

### AUDIT-DEPS-002: CI 供应链安全风险

| 属性 | 值 |
|------|-----|
| **ID** | AUDIT-DEPS-002 |
| **严重级别** | 🟡 Medium |
| **影响范围** | .github/workflows/ |

**描述**:

| 问题 | 文件 | 当前 | 建议 |
|------|------|------|------|
| actions/cache 过时 | ci.yml, ckb.yml | @v2 | @v4 |
| actions/checkout | ci.yml, ckb.yml | @v3 | @v4 |
| ckb-debugger 无校验 | ckb.yml:40-44 | wget 无 SHA | 添加 sha256sum 验证 |

---

### AUDIT-ALIGN-003: __BLST_NO_ASM__ 与 ASM 文件共存矛盾

| 属性 | 值 |
|------|-----|
| **ID** | AUDIT-ALIGN-003 |
| **严重级别** | 🟡 Medium |
| **影响范围** | CKB-VM 构建 |

**描述**:

`src/vect.h:28-32` 中，`BUILD_FOR_CKB_VM` 定义了 `__BLST_NO_ASM__`，这会启用 `no_asm.h` 中的纯 C 实现。但 `build.rs` 同时编译了 RISC-V 汇编文件 (`blst_mul_mont_384.riscv.S`)，并定义了 `USE_MUL_MONT_384_ASM`。

需要确认:
1. `USE_MUL_MONT_384_ASM` 是否正确覆盖了 `__BLST_NO_ASM__` 中的特定函数
2. 是否存在符号冲突（两个实现同时链接）
3. 最终链接的是 C 实现还是 ASM 实现

build.rs 第 114 行还存在一个细节问题: `.define("CKB_DECLARATION_ONLY ", None)` 末尾有一个多余空格。

---

### ⚠️ LOW

---

### AUDIT-LOGIC-003: build.rs 编译器查找循环缺少 break

| 属性 | 值 |
|------|-----|
| **ID** | AUDIT-LOGIC-003 |
| **严重级别** | 🟢 Low |
| **影响范围** | build.rs CKB-VM 构建路径 |

**描述**:

```rust
// bindings/rust/build.rs:98-109
for command in [
    "riscv64-unknown-elf-gcc",
    "riscv64-elf-gcc",
    "riscv64-none-elf-gcc",
] {
    match std::process::Command::new(command).arg("-v").spawn() {
        Ok(_) => {
            cc.compiler(command);
            // ← 缺少 break; 后续成功的编译器会覆盖
        }
        _ => {}
    }
}
```

**修复建议**: 添加 `break;` 在 `cc.compiler(command);` 之后。

---

## 4. 审计覆盖矩阵

| 模块/函数 | DIM-CRYPTO | DIM-MEMORY | DIM-INPUT | DIM-LOGIC | DIM-SERDE | DIM-DEPS | DIM-ALIGN |
|-----------|:----------:|:----------:|:---------:|:---------:|:---------:|:--------:|:---------:|
| **SecretKey::key_gen** | ✅ | ✅ | ✅ | — | — | — | — |
| **SecretKey::serialize** | ❌ | — | — | — | ✅ | — | — |
| **SecretKey::deserialize** | — | — | ✅ | — | ✅ | — | — |
| **PublicKey::validate** | ✅ | — | — | — | — | — | — |
| **PublicKey::deserialize** | — | — | ✅ | — | ✅ | — | — |
| **Signature::verify** | ✅ | ⚠️ | ✅ | — | — | — | — |
| **Signature::aggregate_verify** | ❌ | ❌ | ✅ | ⚠️ | — | — | — |
| **Signature::fast_aggregate_verify** | ✅ | ⚠️ | ✅ | — | — | — | — |
| **verify_multiple_aggregate_signatures** | ❌ | ❌ | ✅ | — | — | — | — |
| **Pairing::aggregate** | — | ❌ | — | — | — | — | ⚠️ |
| **Pairing::mul_n_aggregate** | — | ❌ | — | — | — | — | ⚠️ |
| **Pairing::aggregated** | — | ❌ | — | — | — | — | — |
| **AggregatePublicKey::aggregate** | — | — | ✅ | — | — | — | — |
| **AggregateSignature::aggregate** | — | — | ✅ | — | — | — | — |
| **C: blst_keygen** | ✅ | ❌ | ✅ | — | — | — | — |
| **C: hash_to_field** | ⚠️ | ❌ | — | — | — | — | — |
| **C: aggregate.c (PAIRING)** | — | — | — | ⚠️ | — | — | ⚠️ |
| **ASM: blst_mul_mont_384** | ⚠️ | — | — | — | — | — | ⚠️ |
| **build.rs** | — | — | — | ❌ | — | — | — |
| **CI/CD** | — | — | — | — | — | ❌ | — |
| **Cargo.toml deps** | — | — | — | — | — | ✅ | — |

图例: ✅ 通过 | ❌ 发现问题 | ⚠️ 建议改进/需动态验证 | — 不适用

---

## 5. 依赖安全状态

| 依赖 | 版本 | 类型 | 已知 CVE | 状态 |
|------|------|------|---------|------|
| zeroize | ^1.1 | 运行时 | 无 | ✅ |
| cc | 1.0 | 构建时 | 无 | ✅ |
| glob | 0.3 | 构建时 | 无 | ✅ |
| rand | 0.7 | 开发时 | 无 | ✅ |
| rand_chacha | 0.2 | 开发时 | 无 | ✅ |
| criterion | 0.3 | 开发时 | 无 | ✅ |

**上游 blst 版本差异**: 本仓库 fork 自 supranational/blst，但未标注具体版本。建议与上游最新版本进行安全补丁差异比对。

---

## 6. 改进建议（非漏洞类）

### 6.1 测试覆盖

当前仅 4 个测试函数，覆盖率不足:

| 缺失测试 | 优先级 | 说明 |
|----------|--------|------|
| 反序列化畸形输入 | P0 | 各类 malformed bytes 测试 |
| 空数组边界 | P1 | 0 元素 aggregate/verify |
| 无穷远点输入 | P1 | PK/Sig 为 infinity 的处理 |
| 跨平台一致性 | P1 | x86_64 vs riscv64 结果比对 |
| 模糊测试 | P0 | 反序列化 + 验证路径 |
| 大量签名聚合 | P2 | >1000 签名的 cycle 消耗 |

### 6.2 代码质量

| 建议 | 说明 |
|------|------|
| 移除 `&dyn Any` 模式 | 使用泛型或独立函数替代运行时类型检查 |
| 显式标注 `Send`/`Sync` | `Pairing` 结构体应明确标注线程安全性 |
| 文档化 unsafe 不变量 | 每个 unsafe 块添加 `// SAFETY:` 注释 |
| 固定上游 blst 版本 | 在 README 或 .gitmodules 中记录 fork 基点 |

### 6.3 构建系统

| 建议 | 说明 |
|------|------|
| build.rs:114 空格 | `.define("CKB_DECLARATION_ONLY ", None)` 末尾多余空格 |
| build.sh eval 注入 | `build.sh:43` 的 `eval "$1"` 可执行任意命令 |
| 更新 CI Actions | checkout@v3→v4, cache@v2→v4, codeql-action@v1→v3 |

---

## 7. 附录: 完整 TODO 文档终态

完整 TODO 文档请参见: [`SECURITY_AUDIT_TODO.md`](./SECURITY_AUDIT_TODO.md)

所有 28 项审计 TODO 已完成。发现 12 项问题:
- 3 项 Critical（空指针 UB、alloca 无界、VLA 无界）
- 4 项 High（transmute 滥用、消息唯一性、密钥泄露、panic）
- 4 项 Medium（验证时序、模糊测试、CI 供应链、ASM 矛盾）
- 1 项 Low（编译器查找 bug）

---

*本报告由 AI 安全审计技能生成，遵循 security-audit SKILL.md 方法论。*
*所有"需动态验证"标注的项目需通过实际执行/模糊测试确认。*
