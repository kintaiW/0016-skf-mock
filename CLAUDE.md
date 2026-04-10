# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# 编译检查
cargo check

# 构建动态库（.so / .dll）
cargo build --release

# 运行全部测试（必须单线程，全局设备单例不支持并发）
cargo test

# 运行单个测试
cargo test test_sm2_sign_verify

# 查看测试输出（含 log::debug! 信息）
RUST_LOG=debug cargo test -- --nocapture

# 指定配置文件运行
SKF_MOCK_CONFIG=./mock_keys.toml cargo test
```

> `.cargo/config.toml` 已固定 `RUST_TEST_THREADS=1`，直接 `cargo test` 即可。

## 架构

### 分层结构

```
C 调用者（extern "C" ABI）
    └── ffi/          # #[no_mangle] 薄包装层，仅做参数透传
         └── skf_impl/ # 实际业务逻辑
              └── key_mgr/context.rs  # 全局内存状态
                   └── crypto/        # libsmx 算法封装
```

### 全局状态

`skf_impl/device.rs` 持有唯一全局单例：

```rust
static DEVICE_CTX: OnceLock<Mutex<Option<DeviceContext>>>
```

所有业务函数必须通过 `with_device(|res| { ... })` 访问，`res` 为 `Result<&mut DeviceContext, u32>`（设备未连接时返回 `SAR_FAIL`）。

### 三级句柄层次

| 层级 | 句柄类型 | 基址 | 映射 |
|------|---------|------|-----|
| 应用 | `HAPPLICATION` | 0x1001 | `DeviceContext.app_handles: HashMap<u32, String>` |
| 容器 | `HCONTAINER` | 0x2001 | `DeviceContext.container_handles: HashMap<u32, (String, String)>` |
| 对称密钥 | 密钥句柄 | 0x3001 | `DeviceContext.key_handles: HashMap<u32, SymKeyEntry>` |
| 哈希 | 哈希句柄 | 0x4001 | `DeviceContext.hash_handles: HashMap<u32, HashCtx>` |

所有句柄在 FFI 层统一以 `u32 as usize as *mut c_void` 传递，取回时反向转换。

### 公钥格式转换（重要）

libsmx 与 SKF 规范格式不同，转换全部在 `crypto/sm2_ops.rs`：

| 字段 | libsmx 格式 | SKF `ECCPUBLICKEYBLOB` 格式 |
|------|------------|---------------------------|
| 公钥 | 65字节 `04\|\|x(32)\|\|y(32)` | `XCoordinate[64]` / `YCoordinate[64]`，值**右对齐**（低32字节有效） |
| 签名 | 64字节 `r(32)\|\|s(32)` | `ECCSIGNATUREBLOB.r[64]` / `.s[64]`，右对齐 |
| 密文 | `04\|\|C1.x(32)\|\|C1.y(32)\|\|C3(32)\|\|C2(n)` | `ECCCIPHERBLOB`，`Cipher` 字段 Mock 固定最大 512 字节 |

### 关键实现细节

- **SM4 PKCS7 padding**：libsmx 的 `sm4_encrypt_cbc/ecb` 不含填充，`crypto/sm4_ops.rs` 手工实现 `pkcs7_pad/unpad`。`BLOCKCIPHERPARAM.PaddingType = 1` 表示启用 PKCS7。
- **SM3 增量哈希**：libsmx 仅提供单次 `Sm3Hasher::digest()`，`HashCtx.buffer` 缓冲所有 `DigestUpdate` 数据，在 `DigestFinal` 一次性计算。
- **Z 值计算**：`SKF_DigestInit` 传入公钥时，预先计算 `Z = SM3(entlen||uid||curve_params||pubkey)` 并写入 `buffer` 头部，后续 `DigestUpdate` 直接追加消息。
- **文件 vs 容器**：`SKF_CreateFile/WriteFile/ReadFile` 参数是 `HAPPLICATION`（应用句柄），**不是** `HCONTAINER`。文件挂在应用下。
- **SKF_ImportECCKeyPair 简化**：Mock 中仅存入公钥，私钥用零字节占位（完整解密需容器自身的加密私钥，Mock 不支持）。

### 配置文件

配置文件查找顺序：`SKF_MOCK_CONFIG` 环境变量 → `./mock_keys.toml` → 内置默认值（不报错）。

```toml
[device]
name = "MockSKFDevice"
manufacturer = "Mock Manufacturer"
serial = "MOCK-SKF-001"
label = "Test Token"

[[applications]]
name = "MyApp"
admin_pin = "11111111"
user_pin = "22222222"

  [[applications.containers]]
  name = "MyContainer"
  sign_private_key = "<32字节 hex>"
  sign_public_key_x = "<32字节 hex>"
  sign_public_key_y = "<32字节 hex>"
  sign_cert = "<DER base64>"        # 支持换行
```

### 已实现 vs 桩函数

- **已实现**：设备管理、应用/PIN 管理、容器/文件/证书管理、SM2（签名/验签/加解密/密钥对导出导入）、SM4（ECB/CBC）、SM3（增量/单次/Z值）
- **桩函数（返回 `SAR_NOTSUPPORTYETERR`）**：RSA 全套、ECC 密钥协商（`SKF_GenerateAgreementDataWithECC` 等）、MAC（`SKF_MACInit/MAC/MACUpdate/MACFinal`）

### 错误码速查

| 常量 | 值 | 含义 |
|------|-----|------|
| `SAR_OK` | `0x00000000` | 成功 |
| `SAR_FAIL` | `0x0A000001` | 一般失败（含设备未连接） |
| `SAR_NOTSUPPORTYETERR` | `0x0A000003` | 不支持（RSA/MAC 桩） |
| `SAR_INVALIDHANDLEERR` | `0x0A000005` | 句柄无效 |
| `SAR_INVALIDPARAMERR` | `0x0A000006` | 参数无效（空指针等） |
| `SAR_INDATALENERR` | `0x0A000011` | 输出缓冲太小（标准两阶段查询模式） |
| `SAR_NOTINITIALIZEERR` | `0x0A00000C` | 未调用 EncryptInit/DecryptInit |
| `SAR_KEYNOTFOUNDERR` | `0x0A00001B` | 容器内无对应密钥对 |

## 算法常量

```rust
// GM/T 0016 SKF 标准值（与 GM/T 0018 SDF 不同！）
SGD_SM2_1 = 0x00020100  // 签名密钥（mPlugin JS: SGD_SM2_1）
SGD_SM2_2 = 0x00020200  // 密钥交换
SGD_SM2_3 = 0x00020400  // 加密密钥（mPlugin JS: SGD_SM2_3）
SGD_SM3   = 0x00000001
SGD_SM4_ECB = 0x00000401
SGD_SM4_CBC = 0x00000402
```
