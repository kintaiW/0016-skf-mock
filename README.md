# GM/T 0016-2012 智能密码钥匙模拟动态库 (SKF Mock)

基于 Rust 开发的 GM/T 0016-2012 智能密码钥匙密码应用接口（SKF）纯软件模拟动态库，提供标准 SKF 接口，支持 SM2/SM3/SM4 国密算法，无需真实 USB Key 硬件即可进行开发测试。

## 功能特性

- ✅ **完整 SKF 接口实现**：实现 GM/T 0016-2012 规范约 50 个标准接口
- ✅ **国密算法支持**：SM2 签名/验签/加密/解密、SM3 哈希、SM4 对称加密
- ✅ **三级层次模型**：设备 → 应用 → 容器，符合规范要求
- ✅ **PIN 管理**：支持管理员 PIN 和用户 PIN 验证、修改、解锁
- ✅ **证书管理**：支持证书导入/导出，容器内证书存储
- ✅ **文件管理**：支持应用级文件创建、读写、删除
- ✅ **跨平台**：支持 Windows (.dll) 和 Linux (.so)
- ✅ **mPlugin 集成**：可直接作为 mPlugin 底层 SKF DLL 使用

## 技术栈

- **语言**：Rust 1.75+
- **算法库**：libsmx 0.3（SM2/SM3/SM4）
- **构建类型**：cdylib + rlib（动态库 + 静态库）
- **配置格式**：TOML

## 快速开始

### 构建

```bash
# 编译检查
cargo check

# 构建动态库
cargo build --release

# Windows 输出：target/release/skf_mock.dll
# Linux 输出：target/release/libskf_mock.so
```

### 运行测试

```bash
# 运行全部测试（自动单线程）
cargo test

# 运行单个测试
cargo test test_sm2_sign_verify

# 查看测试输出（含 debug 日志）
RUST_LOG=debug cargo test -- --nocapture
```

### 配置文件

创建 `mock_keys.toml` 配置文件：

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
admin_pin_retry = 6
user_pin_retry = 6

  [[applications.containers]]
  name = "MyContainer"
  # 32字节十六进制私钥
  sign_private_key = "cc54df687d98e2cac86786f469f04c69b280f19a0eccf8bdf15bfeab778cada0"
  sign_public_key_x = "28a446e687b7a4c27e2c4d7a8c9f3b2a1e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9a"
  sign_public_key_y = "3b2a1e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c"
  # DER 格式证书 base64（支持换行）
  sign_cert = """
  MIIB...（base64 DER）
  """
```

**配置文件查找顺序**：
1. 环境变量 `SKF_MOCK_CONFIG` 指定的路径
2. 当前工作目录 `./mock_keys.toml`
3. 内置默认值（不报错）

```bash
# 使用环境变量指定配置文件
SKF_MOCK_CONFIG=/path/to/mock_keys.toml cargo test
```

## 架构设计

### 分层结构

```
C 调用者（extern "C" ABI）
    └── ffi/          # #[no_mangle] 薄包装层，参数透传
         └── skf_impl/ # 实际业务逻辑
              └── key_mgr/context.rs  # 全局内存状态
                   └── crypto/        # libsmx 算法封装
```

### SKF 层次模型

```
设备 (Device)
 └── 应用 (Application)
      ├── PIN (管理员PIN + 用户PIN)
      ├── 文件 (File)
      └── 容器 (Container)
           ├── 签名密钥对 (Sign keypair)
           ├── 加密密钥对 (Encrypt keypair)
           └── 证书 (Certificate)
```

### 全局状态

采用全局单例模式管理设备状态：

```rust
static DEVICE_CTX: OnceLock<Mutex<Option<DeviceContext>>>
```

所有业务函数通过 `with_device(|res| { ... })` 访问，确保线程安全。

### 句柄管理

| 层级 | 句柄类型 | 基址 | 说明 |
|------|---------|------|-----|
| 应用 | `HAPPLICATION` | 0x1001 | 应用句柄 |
| 容器 | `HCONTAINER` | 0x2001 | 容器句柄 |
| 对称密钥 | 密钥句柄 | 0x3001 | SM4 密钥句柄 |
| 哈希 | 哈希句柄 | 0x4001 | SM3 哈希句柄 |

## API 支持

### 已实现接口

#### 设备管理（8个）
- `SKF_EnumDev` - 枚举设备
- `SKF_ConnectDev` - 连接设备
- `SKF_DisConnectDev` - 断开设备
- `SKF_GetDevInfo` - 获取设备信息
- `SKF_GetDevState` - 获取设备状态
- `SKF_SetLabel` - 设置标签
- `SKF_WaitForDevEvent` - 等待设备事件（stub）
- `SKF_CancelWaitForDevEvent` - 取消等待（stub）

#### 应用管理（5个）
- `SKF_CreateApplication` - 创建应用
- `SKF_EnumApplication` - 枚举应用
- `SKF_DeleteApplication` - 删除应用
- `SKF_OpenApplication` - 打开应用
- `SKF_CloseApplication` - 关闭应用

#### PIN 管理（4个）
- `SKF_VerifyPIN` - 校验 PIN
- `SKF_ChangePIN` - 修改 PIN
- `SKF_GetPINInfo` - 获取 PIN 信息
- `SKF_UnblockPIN` - 解锁 PIN

#### 容器管理（5个）
- `SKF_CreateContainer` - 创建容器
- `SKF_DeleteContainer` - 删除容器
- `SKF_EnumContainer` - 枚举容器
- `SKF_OpenContainer` - 打开容器
- `SKF_CloseContainer` - 关闭容器

#### 文件管理（6个）
- `SKF_CreateFile` - 创建文件
- `SKF_DeleteFile` - 删除文件
- `SKF_EnumFiles` - 枚举文件
- `SKF_GetFileInfo` - 获取文件信息
- `SKF_ReadFile` - 读文件
- `SKF_WriteFile` - 写文件

#### ECC 密码服务（10个）
- `SKF_GenECCKeyPair` - 生成 ECC 密钥对
- `SKF_ImportECCKeyPair` - 导入 ECC 密钥对
- `SKF_ECCSignData` - ECC 签名
- `SKF_ECCVerify` - ECC 验签
- `SKF_ECCExportSessionKey` - 导出会话密钥
- `SKF_ExtECCEncrypt` - 外部 ECC 加密
- `SKF_ExtECCDecrypt` - 外部 ECC 解密
- `SKF_ExtECCSign` - 外部 ECC 签名
- `SKF_ExtECCVerify` - 外部 ECC 验签
- `SKF_ExportPublicKey` - 导出公钥
- `SKF_ImportCertificate` - 导入证书
- `SKF_ExportCertificate` - 导出证书

#### 对称密码服务（7个）
- `SKF_SetSymmKey` - 设置对称密钥
- `SKF_EncryptInit` - 加密初始化
- `SKF_Encrypt` - 单组加密
- `SKF_DecryptInit` - 解密初始化
- `SKF_Decrypt` - 单组解密
- `SKF_GenRandom` - 产生随机数

#### 哈希运算（4个）
- `SKF_DigestInit` - 哈希初始化
- `SKF_Digest` - 单组哈希
- `SKF_DigestUpdate` - 哈希更新
- `SKF_DigestFinal` - 哈希结束

### 桩函数（返回 SAR_NOTSUPPORTYETERR）

- **RSA 全套**（6个）：`SKF_GenRSAKeyPair`, `SKF_RSASignData`, `SKF_RSAVerify`, `SKF_RSAExportSessionKey`, `SKF_ExtRSAPubKeyOperation`, `SKF_ExtRSAPriKeyOperation`
- **ECC 密钥协商**（3个）：`SKF_GenerateAgreementDataWithECC`, `SKF_GenerateAgreementDataAndKeyWithECC`, `SKF_GenerateKeyWithECC`
- **MAC**（4个）：`SKF_MACInit`, `SKF_MAC`, `SKF_MACUpdate`, `SKF_MACFinal`
- **设备认证**（2个）：`SKF_DevAuth`, `SKF_ChangeDevAuthKey`

## 与 mPlugin 集成

skf-mock 可直接作为 mPlugin 底层 SKF DLL 使用，无需修改 JS 代码。

### 方式 A：JS 直接指定（推荐）

```js
// 加载 skf-mock 作为底层 DLL
SOF_LoadLibrary("skf_mock.dll");         // Windows
SOF_LoadLibrary("libskf_mock.so");       // Linux
```

### 方式 B：重命名/覆盖原有 DLL

```bash
# Windows
copy target\release\skf_mock.dll  <mPlugin目录>\mtoken_gm3000.dll

# Linux
cp target/release/libskf_mock.so  <mPlugin目录>/libgm3000.1.0.so
```

### mPlugin 接口映射

| JS 接口 | SKF 调用 | 状态 |
|---------|---------|------|
| `SOF_LoadLibrary` | `SKF_ConnectDev` | ✅ |
| `SOF_Login` | `SKF_VerifyPIN` | ✅ |
| `SOF_SignData` | `SKF_ECCSignData` | ✅ |
| `SOF_VerifySignedData` | `SKF_ECCVerify` | ✅ |
| `SOF_Encrypt` | `SKF_ExtECCEncrypt` | ✅ |
| `SOF_Decrypt` | `SKF_ECCDecrypt` | ✅ |
| `SOF_EncryptData` | `SKF_SetSymmKey` + `SKF_Encrypt` | ✅ |
| `SOF_DecryptData` | `SKF_SetSymmKey` + `SKF_Decrypt` | ✅ |
| `SOF_DigestData` | `SKF_DigestInit` + `SKF_Digest` | ✅ |

详细集成指南请参考 [docs/mPlugin-integration.md](docs/mPlugin-integration.md)。

## 关键实现细节

### 公钥格式转换

libsmx 与 SKF 规范格式不同，转换在 `crypto/sm2_ops.rs` 中实现：

| 字段 | libsmx 格式 | SKF 格式 |
|------|------------|----------|
| 公钥 | 65字节 `04\|\|x(32)\|\|y(32)` | `XCoordinate[64]` / `YCoordinate[64]`（右对齐） |
| 签名 | 64字节 `r(32)\|\|s(32)` | `ECCSIGNATUREBLOB.r[64]` / `.s[64]`（右对齐） |
| 密文 | `04\|\|C1.x(32)\|\|C1.y(32)\|\|C3(32)\|\|C2(n)` | `ECCCIPHERBLOB` 结构 |

### SM4 PKCS7 填充

libsmx 的 SM4 不含填充，`crypto/sm4_ops.rs` 手工实现 PKCS7 填充/去填充。`BLOCKCIPHERPARAM.PaddingType = 1` 启用填充。

### SM3 增量哈希

libsmx 仅提供单次 `Sm3Hasher::digest()`，`HashCtx.buffer` 缓冲所有 `DigestUpdate` 数据，在 `DigestFinal` 一次性计算。

### Z 值计算

`SKF_DigestInit` 传入公钥时，预先计算 `Z = SM3(entlen||uid||curve_params||pubkey)` 并写入缓冲头部，后续 `DigestUpdate` 直接追加消息。

## 已知限制

| 限制项 | 说明 |
|--------|------|
| RSA 算法 | 不支持，返回 `SAR_NOTSUPPORTYETERR` |
| ECC 密钥协商 | 不支持，返回 `SAR_NOTSUPPORTYETERR` |
| MAC 运算 | 不支持，返回 `SAR_NOTSUPPORTYETERR` |
| 多设备并发 | 不支持，全局单例仅支持单设备 |
| `SKF_ImportECCKeyPair` 私钥 | 简化实现，仅存公钥，私钥用零字节占位 |

## 开发指南

### 项目结构

```
0016-skf-mock/
├── Cargo.toml
├── mock_keys.toml           # 密钥与应用配置
├── README.md
├── projectplan.md
├── docs/
│   └── mPlugin-integration.md
└── src/
    ├── lib.rs               # 库入口
    ├── error_code.rs        # SAR_* 错误码
    ├── types.rs             # #[repr(C)] 结构体
    ├── config/              # 配置文件解析
    ├── key_mgr/             # 全局状态管理
    ├── crypto/              # SM2/SM3/SM4 封装
    ├── skf_impl/            # 业务逻辑实现
    └── ffi/                 # extern "C" 导出
```

### 错误码速查

| 常量 | 值 | 含义 |
|------|-----|------|
| `SAR_OK` | `0x00000000` | 成功 |
| `SAR_FAIL` | `0x0A000001` | 一般失败 |
| `SAR_NOTSUPPORTYETERR` | `0x0A000003` | 不支持 |
| `SAR_INVALIDHANDLEERR` | `0x0A000005` | 句柄无效 |
| `SAR_INVALIDPARAMERR` | `0x0A000006` | 参数无效 |
| `SAR_INDATALENERR` | `0x0A000011` | 输出缓冲太小 |
| `SAR_NOTINITIALIZEERR` | `0x0A00000C` | 未初始化 |
| `SAR_KEYNOTFOUNDERR` | `0x0A00001B` | 密钥未找到 |

### 算法常量

```rust
// GM/T 0016 SKF 标准值
SGD_SM2_1 = 0x00020100  // 签名密钥
SGD_SM2_2 = 0x00020200  // 密钥交换
SGD_SM2_3 = 0x00020400  // 加密密钥
SGD_SM3   = 0x00000001
SGD_SM4_ECB = 0x00000401
SGD_SM4_CBC = 0x00000402
```

## 许可证

Apache License 2.0

## 参考资料

- GM/T 0016-2012 智能密码钥匙密码应用接口规范
- [libsmx 文档](https://docs.rs/libsmx/)
- [mPlugin 集成指南](docs/mPlugin-integration.md)
