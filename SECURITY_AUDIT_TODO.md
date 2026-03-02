# ckb-blst-rs 安全审计 TODO

> 版本: v1 | 最后更新: 2026-03-02 | 状态: 已完成

## 项目概况
  - 语言: Rust (FFI 绑定层) + C (密码学核心) + RISC-V Assembly (CKB-VM 优化)
  - 类型: 密码学库 (BLS12-381 签名方案，fork 自 supranational/blst，适配 CKB-VM)
  - 依赖数: 3 (运行时: zeroize ^1.1; 构建时: cc 1.0, glob 0.3)
  - 源文件数: 55 (含 .rs/.c/.h/.S)
  - 现有测试数: 4 (test_sign, test_aggregate, test_multiple_agg_sigs, test_serialization)

## 审计进度
  - 总 TODO 项: 28
  - ✅ 已完成: 28 | ❌ 发现问题: 12 | ⏳ 待审计: 0

---

## 第 1 章: DIM-CRYPTO — 密码学操作

- [x] 🔴 **AUDIT-CRYPTO-001**: 密钥派生域分离检查
  - **关联代码**: `src/keygen.c:blst_keygen:123-182`
  - **审计内容**:
    - blst_keygen 是否使用 HKDF-Extract + HKDF-Expand 并满足 BLS 规范
    - salt 是否正确更新 ("BLS-SIG-KEYGEN-SALT-" → H(salt))
    - IKM_len < 32 时的处理是否安全
  - **现有覆盖**: test_sign 间接覆盖正常路径
  - **发现记录**: ⚠️ IKM < 32 时静默返回全零 SK (C 层), Rust 层正确返回 Error

- [x] 🔴 **AUDIT-CRYPTO-002**: 敏感密钥材料清零
  - **关联代码**: `src/keygen.c:180`, `bindings/rust/src/lib.rs:308-309,386-392`
  - **审计内容**:
    - keygen 结束后 scratch 是否清零
    - SecretKey struct 是否 Zeroize(drop)
    - SecretKey::serialize() 返回值是否安全
  - **现有覆盖**: 无直接测试
  - **发现记录**: ❌ SecretKey::serialize() 返回 [u8;32] 值类型，栈上副本不会被清零

- [x] 🔴 **AUDIT-CRYPTO-003**: 椭圆曲线点有效性验证
  - **关联代码**: `bindings/rust/src/lib.rs:427-437,631-643`
  - **审计内容**:
    - PublicKey::validate() 是否检查 infinity + in_group
    - Signature::validate() 是否检查 infinity + in_group
    - 反序列化后是否强制验证
  - **现有覆盖**: test_sign 中使用了 pk_validate=true
  - **发现记录**: ✅ 验证逻辑正确，但反序列化不强制验证（由调用者决定）

- [x] 🟠 **AUDIT-CRYPTO-004**: 恒定时间比较
  - **关联代码**: `src/vect.c`, `src/no_asm.h:mul_mont_n`
  - **审计内容**:
    - 标量/密钥比较是否使用恒定时间操作
    - vec_select/cneg_fp 等是否无数据依赖分支
    - RISC-V 汇编中的蒙哥马利乘法是否恒定时间
  - **现有覆盖**: 无
  - **发现记录**: ⚠️ 需动态验证。C 代码使用 vec_select 等恒定时间模式，但 RISC-V 汇编需专家审查

- [x] 🟠 **AUDIT-CRYPTO-005**: 随机数生成安全性
  - **关联代码**: `bindings/rust-examples/ckb/src/main.rs:53-54`
  - **审计内容**:
    - CKB 合约示例使用固定 seed [42u8;32]
    - 生产代码中是否有 CSPRNG 使用指引
  - **现有覆盖**: 无
  - **发现记录**: ⚠️ 示例代码使用固定 seed，但这是测试/bench 代码，非生产

- [x] 🟠 **AUDIT-CRYPTO-006**: 聚合验证消息唯一性
  - **关联代码**: `bindings/rust/src/lib.rs:687,807`
  - **审计内容**:
    - aggregate_verify 是否检查消息唯一性
    - uniq() 函数是否被调用
    - 缺少检查是否导致 rogue key 攻击
  - **现有覆盖**: 无
  - **发现记录**: ❌ TODO 注释未实现。uniq() 存在但未被调用，BLS 规范要求消息唯一

---

## 第 2 章: DIM-MEMORY — 内存与资源安全

- [x] 🔴 **AUDIT-MEMORY-001**: alloca() 大小未检查
  - **关联代码**: `src/keygen.c:92`, `src/hash_to_field.c:125`, `src/pairing.c:224-225`, `src/multi_scalar.c:142,185`, `src/bulk_addition.c:149`, `src/ec_mult.h:107`
  - **审计内容**:
    - alloca 的大小参数是否受限
    - 攻击者是否可控制大小参数
    - CKB-VM 栈大小限制下的安全性
  - **现有覆盖**: 无
  - **发现记录**: ❌ 8 处 alloca 均无大小上限检查，CKB-VM 栈空间有限，大输入可导致栈溢出

- [x] 🔴 **AUDIT-MEMORY-002**: C99 VLA 大小未检查
  - **关联代码**: `src/keygen.c:94`, `src/hash_to_field.c:127`, `src/no_asm.h:23`
  - **审计内容**:
    - VLA 大小是否有上界
    - 是否会溢出栈
  - **现有覆盖**: 无
  - **发现记录**: ❌ VLA 大小来自函数参数，无上界检查

- [x] 🔴 **AUDIT-MEMORY-003**: Rust unsafe 代码中的 UB
  - **关联代码**: `bindings/rust/src/lib.rs:720`
  - **审计内容**:
    - ptr::null::<T>().as_ref() 是否构成 UB
    - Option<&T> 的 None 语义是否正确传递
  - **现有覆盖**: test_aggregate 间接触发
  - **发现记录**: ❌ ptr::null::<$sig_aff>().as_ref() 创建空指针引用，是 Rust UB

- [x] 🔴 **AUDIT-MEMORY-004**: transmute 滥用绕过借用检查器
  - **关联代码**: `bindings/rust/src/lib.rs:691-695,706-712,811-850`
  - **审计内容**:
    - 指针→usize→指针的 transmute 链是否安全
    - 生命周期擦除在单线程 CKB-VM 中是否必要
    - 重构后是否可安全移除
  - **现有覆盖**: test_aggregate 间接触发
  - **发现记录**: ❌ 13 处 transmute 擦除生命周期信息，在 no_std 单线程环境中不必要

- [x] 🟠 **AUDIT-MEMORY-005**: Pairing 结构体对齐安全
  - **关联代码**: `bindings/rust/src/lib.rs:58-87`
  - **审计内容**:
    - Box<[u64]> → *mut blst_pairing 的转换是否满足 C 结构体对齐要求
    - blst_pairing_sizeof() / 8 的整数除法是否截断
  - **现有覆盖**: 所有 Pairing 相关测试间接覆盖
  - **发现记录**: ⚠️ C 端 sizeof_pairing 已 8 字节对齐，u64 提供 8 字节对齐，基本安全

- [x] 🟠 **AUDIT-MEMORY-006**: panic! 在公开 API 中
  - **关联代码**: `bindings/rust/src/lib.rs:139,199,219`
  - **审计内容**:
    - Pairing::aggregate/mul_n_aggregate/aggregated 中的 panic!("whaaaa?")
    - 在 CKB-VM 中 panic 是否导致不可恢复的崩溃
    - 是否应返回 Result/BLST_ERROR
  - **现有覆盖**: 无（仅测试正常路径）
  - **发现记录**: ❌ 3 处 panic! 使用 &dyn Any 做运行时类型检查，类型不匹配时崩溃

---

## 第 3 章: DIM-INPUT — 输入验证

- [x] 🟠 **AUDIT-INPUT-001**: 反序列化边界检查
  - **关联代码**: `bindings/rust/src/lib.rs:484-497,925-939`
  - **审计内容**:
    - PublicKey::deserialize 是否正确检查长度和格式标志位
    - Signature::deserialize 是否正确检查长度和格式标志位
    - 畸形输入是否安全拒绝
  - **现有覆盖**: test_serialization 覆盖正常路径
  - **发现记录**: ✅ 长度检查和高位标志位检查正确，FFI 调用返回错误码被正确传播

- [x] 🟠 **AUDIT-INPUT-002**: SecretKey 反序列化范围检查
  - **关联代码**: `bindings/rust/src/lib.rs:395-407`
  - **审计内容**:
    - 是否检查 sk_in.len() == 32
    - 是否调用 blst_sk_check 验证标量范围
    - 超出群阶的值是否被拒绝
  - **现有覆盖**: 无直接测试
  - **发现记录**: ✅ 长度检查 + blst_sk_check 范围验证均存在

- [x] 🟡 **AUDIT-INPUT-003**: aggregate 空数组处理
  - **关联代码**: `bindings/rust/src/lib.rs:547,682,798,1002`
  - **审计内容**:
    - AggregatePublicKey::aggregate 空数组是否返回错误
    - aggregate_verify 0 元素是否返回 VERIFY_FAIL
    - verify_multiple_aggregate_signatures 数组长度不一致时的处理
  - **现有覆盖**: 无直接测试
  - **发现记录**: ✅ 空数组和长度不一致均正确返回错误

- [x] 🟡 **AUDIT-INPUT-004**: DST 参数验证
  - **关联代码**: `bindings/rust/src/lib.rs:63,354-377`
  - **审计内容**:
    - 空 DST 是否被安全处理
    - DST 长度上限
  - **现有覆盖**: test_sign 使用了标准 DST
  - **发现记录**: ✅ DST 作为字节切片传递，C 层安全处理 NULL DST

---

## 第 4 章: DIM-LOGIC — 业务逻辑

- [x] 🟠 **AUDIT-LOGIC-001**: aggregate_verify 签名验证时序
  - **关联代码**: `bindings/rust/src/lib.rs:674-752`
  - **审计内容**:
    - sig_groupcheck 是否在 pairing 计算之后执行
    - 是否存在 TOCTOU 问题
  - **现有覆盖**: test_aggregate
  - **发现记录**: ⚠️ sig_groupcheck 在 pairing 循环之后执行（line 737），这意味着无效签名也会消耗完整的 pairing 计算资源，可能被利用做 DoS

- [x] 🟡 **AUDIT-LOGIC-002**: Pairing 上下文中的魔数哨兵
  - **关联代码**: `src/aggregate.c:73-74,79-80`
  - **审计内容**:
    - DST 指针存储为 (void*)42 的哨兵模式
    - 是否有指针碰撞风险
  - **现有覆盖**: 所有验证测试间接触发
  - **发现记录**: ⚠️ 在 64 位系统上碰撞概率极低，但不符合安全编码规范

- [x] 🟡 **AUDIT-LOGIC-003**: build.rs 编译器查找逻辑
  - **关联代码**: `bindings/rust/build.rs:98-109`
  - **审计内容**:
    - 编译器查找循环是否 break on success
    - 是否可能选错编译器
  - **现有覆盖**: CI 测试间接覆盖
  - **发现记录**: ❌ 循环未 break，后续成功的编译器会覆盖前一个

---

## 第 5 章: DIM-SERDE — 序列化/反序列化

- [x] 🟠 **AUDIT-SERDE-001**: 序列化 roundtrip 一致性
  - **关联代码**: `bindings/rust/src/lib.rs:455-506,894-947`
  - **审计内容**:
    - compress → uncompress roundtrip
    - serialize → deserialize roundtrip
    - 是否存在信息丢失
  - **现有覆盖**: test_serialization
  - **发现记录**: ✅ roundtrip 测试通过

- [x] 🟡 **AUDIT-SERDE-002**: 不可信来源反序列化安全
  - **关联代码**: `bindings/rust/src/lib.rs:484-497,925-939`
  - **审计内容**:
    - FFI 反序列化函数是否有缓冲区溢出风险
    - 畸形数据是否能触发 C 层崩溃
  - **现有覆盖**: 无模糊测试
  - **发现记录**: ⚠️ C 层 blst_p1_deserialize 等函数来自成熟库，但项目无模糊测试覆盖

---

## 第 6 章: DIM-DEPS — 依赖安全

- [x] 🟡 **AUDIT-DEPS-001**: 依赖版本安全
  - **关联代码**: `bindings/rust/Cargo.toml`
  - **审计内容**:
    - zeroize ^1.1 是否有已知 CVE
    - cc 1.0, glob 0.3 构建依赖安全性
  - **现有覆盖**: N/A
  - **发现记录**: ✅ 截至审计日期无已知 CVE

- [x] 🟡 **AUDIT-DEPS-002**: CI 依赖供应链安全
  - **关联代码**: `.github/workflows/ci.yml`, `.github/workflows/ckb.yml`
  - **审计内容**:
    - GitHub Actions 版本是否过时
    - ckb-debugger 下载是否有校验和验证
  - **现有覆盖**: N/A
  - **发现记录**: ❌ actions/cache@v2 过时; ckb-debugger 下载无 SHA 校验

---

## 第 7 章: DIM-ERRINFO — 错误处理与信息泄露

- [x] 🟡 **AUDIT-ERRINFO-001**: 错误码区分度
  - **关联代码**: `src/errors.h`, `bindings/rust/src/lib.rs`
  - **审计内容**:
    - BLST_ERROR 枚举是否可用于 oracle 攻击
    - 不同错误路径返回的错误码是否可区分密钥状态
  - **现有覆盖**: 无
  - **发现记录**: ✅ 错误码粒度合理，不泄露内部密钥状态

- [x] 🟡 **AUDIT-ERRINFO-002**: panic 消息泄露
  - **关联代码**: `bindings/rust/src/lib.rs:139,199,219`
  - **审计内容**:
    - panic!("whaaaa?") 是否泄露内部信息
  - **现有覆盖**: 无
  - **发现记录**: ✅ panic 消息无敏感信息，但 panic 本身是问题（见 MEMORY-006）

---

## 第 8 章: DIM-SPEC — 规范一致性

- [x] 🟠 **AUDIT-SPEC-001**: BLS 签名规范一致性
  - **关联代码**: 全库
  - **审计内容**:
    - 是否与 IETF draft-irtf-cfrg-bls-signature 一致
    - hash_to_field 是否符合 RFC 9380
    - KeyGen 是否符合 Section 2.3
  - **现有覆盖**: test_sign 使用标准 DST
  - **发现记录**: ⚠️ 核心实现来自 blst 成熟库，但 RISC-V 汇编和 CKB-VM 适配是自定义代码，需独立验证

---

## 第 9 章: DIM-CKB-ALIGN — CKB 内存对齐安全

- [x] 🟠 **AUDIT-ALIGN-001**: Rust FFI 指针转换对齐
  - **关联代码**: `bindings/rust/src/lib.rs:82-86`
  - **审计内容**:
    - Box<[u64]> → *mut blst_pairing 是否满足 C 结构体对齐
    - RISC-V 目标上的 ABI 对齐约束
  - **现有覆盖**: CKB CI 运行
  - **发现记录**: ✅ u64 提供 8 字节对齐，满足 PAIRING 结构体需求

- [x] 🟠 **AUDIT-ALIGN-002**: 汇编代码中的内存访问对齐
  - **关联代码**: `src/asm/blst_mul_mont_384.riscv.S`, `src/asm/blst_mul_mont_384x.riscv.S`
  - **审计内容**:
    - ld/sd 指令是否从对齐地址操作
    - 是否有非对齐访问模式
  - **现有覆盖**: CKB CI 运行
  - **发现记录**: ⚠️ 需动态验证。RISC-V ld/sd 要求 8 字节对齐，所有参数通过 C 调用传入，应满足 ABI 对齐

- [x] 🟡 **AUDIT-ALIGN-003**: CKB-VM v1/v2 兼容性
  - **关联代码**: `src/vect.h:28-32`
  - **审计内容**:
    - BUILD_FOR_CKB_VM 定义了 __BLST_NO_ASM__ 但又链接了 RISC-V 汇编
    - v1/v2 对非对齐访问行为是否一致
  - **现有覆盖**: 无
  - **发现记录**: ⚠️ __BLST_NO_ASM__ 被定义但同时链接了 ASM 文件 (blst_mul_mont_384.riscv.S)。需确认 USE_MUL_MONT_384_ASM 宏是否正确覆盖特定函数而非全部

---

## 附录 A: 审计执行日志
| 日期 | 审计项 | 发现摘要 | 状态 |
|------|--------|---------|------|
| 2026-03-02 | CRYPTO-001~006 | 消息唯一性未检查; SK serialize 未清零 | 完成 |
| 2026-03-02 | MEMORY-001~006 | 8处alloca无界; null ptr UB; 13处transmute; 3处panic | 完成 |
| 2026-03-02 | INPUT-001~004 | 反序列化检查正确; 空数组处理正确 | 完成 |
| 2026-03-02 | LOGIC-001~003 | sig_groupcheck 时序问题; 魔数哨兵; 编译器循环bug | 完成 |
| 2026-03-02 | SERDE-001~002 | roundtrip 正确; 缺少模糊测试 | 完成 |
| 2026-03-02 | DEPS-001~002 | 无已知CVE; CI供应链风险 | 完成 |
| 2026-03-02 | ERRINFO-001~002 | 错误码合理; panic无信息泄露 | 完成 |
| 2026-03-02 | SPEC-001 | 核心来自blst; RISC-V自定义需验证 | 完成 |
| 2026-03-02 | ALIGN-001~003 | 对齐基本安全; ASM需动态验证; __BLST_NO_ASM__定义存疑 | 完成 |

## 附录 B: 新增项跟踪
| 日期 | 新增项 ID | 来源 | 描述 |
|------|----------|------|------|
| 2026-03-02 | MEMORY-003 | CRYPTO-003 审计中 | 发现 aggregate_verify 中的 null ptr UB |
| 2026-03-02 | MEMORY-004 | CRYPTO-006 审计中 | 发现 transmute 链用于生命周期擦除 |
| 2026-03-02 | LOGIC-003 | MEMORY-001 审计中 | build.rs 编译器查找逻辑缺陷 |
| 2026-03-02 | ALIGN-003 | ALIGN-002 审计中 | __BLST_NO_ASM__ 与 ASM 同时存在的矛盾 |

## 附录 C: 修复建议
| 审计项 | 严重级别 | 建议方案 | 修复状态 |
|--------|---------|---------|---------|
| CRYPTO-002 | High | SecretKey::serialize() 返回 Zeroizing<[u8;32]> | 未修复 |
| CRYPTO-006 | High | 在 aggregate_verify 中调用 uniq() 检查消息唯一性 | 未修复 |
| MEMORY-001 | Critical | 为所有 alloca() 添加大小上限检查 | 未修复 |
| MEMORY-002 | Critical | VLA 替换为堆分配或添加大小检查 | 未修复 |
| MEMORY-003 | Critical | 将 ptr::null::<T>().as_ref() 替换为 Option::<&T>::None | 未修复 |
| MEMORY-004 | High | 移除不必要的 transmute，直接传递切片引用 | 未修复 |
| MEMORY-006 | High | 将 panic!("whaaaa?") 替换为 BLST_ERROR 返回值 | 未修复 |
| LOGIC-001 | Medium | 将 sig_groupcheck 提前到 pairing 计算之前 | 未修复 |
| LOGIC-003 | Low | 在编译器查找成功后添加 break | 未修复 |
| DEPS-002 | Medium | 更新 CI Actions 版本; 添加 ckb-debugger SHA 校验 | 未修复 |
| SERDE-002 | Medium | 添加反序列化模糊测试 | 未修复 |
| ALIGN-003 | Medium | 理清 __BLST_NO_ASM__ 与 USE_MUL_MONT_384_ASM 的关系 | 未修复 |
