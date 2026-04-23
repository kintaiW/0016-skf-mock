# GM/T 0016-2012 智能密码钥匙模拟动态库 - 设计与开发执行计划

## 一、项目概述

**目标**：基于 Rust 开发 GM/T 0016-2012 智能密码钥匙密码应用接口（SKF）的纯软件模拟动态库（cdylib），以 `extern "C"` 形式对外提供标准 SKF 接口，支持 SM2/SM3/SM4 国密算法，无需真实 USB Key 硬件即可进行开发测试。

**参考文档**：
- `docs/GMT 0016-2012 智能密码钥匙密码应用接口规范.PDF`（标准规范，37页）

**参考项目**：`0018-sdk-mock`（GM/T 0018 SDF 模拟 SDK，架构与代码风格参考）

**技术栈**：Rust 1.75+，libsmx 0.3.0（SM2/SM3/SM4），crate-type = ["cdylib", "rlib"]

---

## 二、SKF 接口模型与架构设计

### 2.1 SKF 层次模型

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

**三类句柄**：
- `DEVHANDLE` — 设备句柄
- `HAPPLICATION` — 应用句柄
- `HCONTAINER` — 容器句柄

**调用流程约束**：
```
SKF_ConnectDev → SKF_OpenApplication → SKF_VerifyPIN
  → SKF_OpenContainer → 密码运算 → SKF_CloseContainer
  → SKF_CloseApplication → SKF_DisConnectDev
```

### 2.2 架构分层（参考 0018-sdk-mock）

```
C 调用方 / FFI 边界
    ↓  src/ffi/          — extern "C" 导出，指针安全检查，类型转换
    ↓  src/skf_impl/     — GM/T 0016 业务逻辑（设备/应用/容器/密码运算）
    ↓  src/crypto/       — 算法薄封装（对接 libsmx）
    ↓  src/key_mgr/      — 内存密钥仓库 + 设备/应用/容器上下文
    ↓  src/config/       — mock_keys.toml 解析
```

### 2.3 全局状态设计

```rust
// 设备单例（参考 0018 的 DEVICE_CTX 模式）
static DEVICE_CTX: OnceLock<Mutex<Option<DeviceContext>>> = OnceLock::new();

DeviceContext {
    applications: HashMap<String, Application>,  // 应用名 → 应用
    connected: bool,
}

Application {
    admin_pin: PinInfo,      // 管理员 PIN
    user_pin: PinInfo,       // 用户 PIN
    files: HashMap<String, FileData>,    // 文件名 → 文件数据
    containers: HashMap<String, Container>,  // 容器名 → 容器
}

Container {
    sign_keypair: Option<(PrivKey, PubKey)>,
    enc_keypair: Option<(PrivKey, PubKey)>,
    sign_cert: Option<Vec<u8>>,
    enc_cert: Option<Vec<u8>>,
}
```

**句柄管理**：使用 AtomicU32 递增生成句柄，HashMap 映射句柄到对象引用。
- 设备句柄：固定值 1（单设备模式）
- 应用句柄：从 0x1001 开始
- 容器句柄：从 0x2001 开始

---

## 三、数据结构定义

### 3.1 设备信息（DEVINFO）

```rust
#[repr(C)]
pub struct DEVINFO {
    pub Version: VERSION,           // 版本
    pub Manufacturer: [u8; 64],     // 厂商信息
    pub Issuer: [u8; 64],           // 发行者信息
    pub Label: [u8; 32],            // 标签
    pub SerialNumber: [u8; 32],     // 序列号
    pub HWVersion: VERSION,         // 硬件版本
    pub FirmwareVersion: VERSION,   // 固件版本
    pub AlgSymCap: u32,             // 对称算法能力
    pub AlgAsymCap: u32,            // 非对称算法能力
    pub AlgHashCap: u32,            // 哈希算法能力
    pub DevAuthAlgId: u32,          // 设备认证算法标识
    pub TotalSpace: u32,            // 总空间
    pub FreeSpace: u32,             // 可用空间
    pub MaxECCBufferSize: u32,      // 最大 ECC 缓冲区
    pub MaxBufferSize: u32,         // 最大缓冲区
    pub Reserved: [u8; 64],         // 保留
}

#[repr(C)]
pub struct VERSION {
    pub major: u8,
    pub minor: u8,
}
```

### 3.2 ECC 相关结构

```rust
#[repr(C)]
pub struct ECCPUBLICKEYBLOB {
    pub BitLen: u32,
    pub XCoordinate: [u8; 64],  // 右对齐大端
    pub YCoordinate: [u8; 64],
}

#[repr(C)]
pub struct ECCSIGNATUREBLOB {
    pub r: [u8; 64],
    pub s: [u8; 64],
}

#[repr(C)]
pub struct ECCCIPHERBLOB {
    pub XCoordinate: [u8; 64],
    pub YCoordinate: [u8; 64],
    pub HASH: [u8; 32],
    pub CipherLen: u32,
    pub Cipher: [u8; 1],  // 变长，实际按 CipherLen 分配
}

#[repr(C)]
pub struct BLOCKCIPHERPARAM {
    pub IV: [u8; 32],
    pub IVLen: u32,
    pub PaddingType: u32,
    pub FeedBitLen: u32,
}
```

### 3.3 数字信封结构

```rust
#[repr(C)]
pub struct ENVELOPEDKEYBLOB {
    pub Version: u32,
    pub ulSymmAlgID: u32,
    pub ulBits: u32,
    pub cbEncryptedPriKey: [u8; 64],   // 加密后的私钥
    pub PubKey: ECCPUBLICKEYBLOB,
    pub ECCCipherBlob: ECCCIPHERBLOB,
}
```

### 3.4 文件属性

```rust
#[repr(C)]
pub struct FILEATTRIBUTE {
    pub FileName: [u8; 32],
    pub FileSize: u32,
    pub ReadRights: u32,
    pub WriteRights: u32,
}
```

---

## 四、错误码定义

| 错误码 | 常量名 | 说明 |
|--------|--------|------|
| 0x00000000 | SAR_OK | 成功 |
| 0x0A000001 | SAR_FAIL | 失败 |
| 0x0A000002 | SAR_UNKNOWNERR | 未知错误 |
| 0x0A000003 | SAR_NOTSUPPORTYETERR | 不支持的接口调用 |
| 0x0A000004 | SAR_FILEERR | 文件操作错误 |
| 0x0A000005 | SAR_INVALIDHANDLEERR | 无效句柄 |
| 0x0A000006 | SAR_INVALIDPARAMERR | 无效参数 |
| 0x0A000007 | SAR_READFILEERR | 读文件错误 |
| 0x0A000008 | SAR_WRITEFILEERR | 写文件错误 |
| 0x0A000009 | SAR_NAMELENERR | 名称长度错误 |
| 0x0A00000A | SAR_KEYUSAGEERR | 密钥用途错误 |
| 0x0A00000B | SAR_MODULUSLENERR | 模长错误 |
| 0x0A00000C | SAR_NOTINITIALIZEERR | 未初始化 |
| 0x0A00000D | SAR_OBJERR | 对象错误 |
| 0x0A00000E | SAR_MEMORYERR | 内存错误 |
| 0x0A00000F | SAR_TIMEOUTERR | 超时 |
| 0x0A000010 | SAR_INDATAERR | 输入数据错误 |
| 0x0A000011 | SAR_INDATALENERR | 输入数据长度错误 |
| 0x0A000012 | SAR_OUTDATAERR | 输出数据错误 |
| 0x0A000013 | SAR_OUTDATALENERR | 输出数据长度错误 |
| 0x0A000014 | SAR_HASHOBJINITERR | 哈希对象初始化错误 |
| 0x0A000015 | SAR_HASHPARAMERR | 哈希参数错误 |
| 0x0A000016 | SAR_HASHNOTINITIALIZEERR | 哈希未初始化 |
| 0x0A000017 | SAR_HASHINTERR | 哈希内部错误 |
| 0x0A000018 | SAR_GENABORTERR | 生成终止错误 |
| 0x0A000019 | SAR_KEYNOTINITIALIZEERR | 密钥未初始化 |
| 0x0A00001A | SAR_CERTDNOTMATCHERR | 证书不匹配 |
| 0x0A00001B | SAR_KEYNOTFOUNDERR | 密钥未找到 |
| 0x0A00001C | SAR_CERTNOTFOUNDERR | 证书未找到 |
| 0x0A00001D | SAR_NOTEXPORTERR | 无法导出 |
| 0x0A00001E | SAR_DECLOADERR | 解密加载失败 |
| 0x0A000020 | SAR_APPLICATION_NOT_EXISTS | 应用不存在 |
| 0x0A000021 | SAR_APPLICATION_EXISTS | 应用已存在 |
| 0x0A000022 | SAR_USER_ALREADY_LOGGED_IN | 用户已登录 |
| 0x0A000023 | SAR_USER_PIN_NOT_INITIALIZED | 用户 PIN 未初始化 |
| 0x0A000024 | SAR_USER_TYPE_INVALID | 用户类型无效 |
| 0x0A000025 | SAR_AUTHCODEERR | 认证码错误 |
| 0x0A000026 | SAR_AUTHCODETOOLONGERR | 认证码太长 |
| 0x0A000027 | SAR_CONTAINER_NOT_EXISTS | 容器不存在 |
| 0x0A000028 | SAR_CONTAINER_EXISTS | 容器已存在 |
| 0x0A000029 | SAR_PIN_INCORRECT | PIN 不正确 |
| 0x0A00002A | SAR_PIN_LOCKED | PIN 已锁定 |

---

## 五、接口清单（~50个函数）

### 5.1 设备管理（8个）

| 函数 | 功能 | 实现方式 |
|------|------|---------|
| SKF_WaitForDevEvent | 等待设备插入事件 | stub：直接返回设备名 |
| SKF_CancelWaitForDevEvent | 取消等待 | stub：返回 SAR_OK |
| SKF_EnumDev | 枚举设备 | 返回预配置的设备名 |
| SKF_ConnectDev | 连接设备 | 初始化 DeviceContext |
| SKF_DisConnectDev | 断开设备 | 销毁 DeviceContext |
| SKF_GetDevState | 获取设备状态 | 返回"已就绪" |
| SKF_SetLabel | 设置标签 | 内存修改 |
| SKF_GetDevInfo | 获取设备信息 | 返回预配置 DEVINFO |

### 5.2 设备认证（3个）

| 函数 | 功能 | 实现方式 |
|------|------|---------|
| SKF_DevAuth | 设备认证 | stub：直接返回成功 |
| SKF_ChangeDevAuthKey | 更改设备认证密钥 | stub：返回成功 |
| SKF_GenRandom | 产生随机数 | 用 OsRng 填充 |

### 5.3 访问控制（4个）

| 函数 | 功能 | 实现方式 |
|------|------|---------|
| SKF_VerifyPIN | 校验 PIN | 比对配置中的 PIN |
| SKF_ChangePIN | 修改 PIN | 内存修改 PIN 值 |
| SKF_GetPINInfo | 获取 PIN 信息 | 返回重试次数等 |
| SKF_UnblockPIN | 解锁 PIN | 用管理员 PIN 解锁用户 PIN |

### 5.4 应用管理（5个）

| 函数 | 功能 | 实现方式 |
|------|------|---------|
| SKF_CreateApplication | 创建应用 | 内存创建 Application |
| SKF_EnumApplication | 枚举应用 | 返回应用名列表 |
| SKF_DeleteApplication | 删除应用 | 内存删除 |
| SKF_OpenApplication | 打开应用 | 返回应用句柄 |
| SKF_CloseApplication | 关闭应用 | 释放应用句柄 |

### 5.5 文件管理（6个 stub）

| 函数 | 功能 | 实现方式 |
|------|------|---------|
| SKF_CreateFile | 创建文件 | 内存创建 |
| SKF_DeleteFile | 删除文件 | 内存删除 |
| SKF_EnumFiles | 枚举文件 | 返回文件名列表 |
| SKF_GetFileInfo | 获取文件信息 | 返回 FILEATTRIBUTE |
| SKF_ReadFile | 读文件 | 从内存读取 |
| SKF_WriteFile | 写文件 | 写入内存 |

### 5.6 容器管理（5个）

| 函数 | 功能 | 实现方式 |
|------|------|---------|
| SKF_CreateContainer | 创建容器 | 内存创建 Container |
| SKF_DeleteContainer | 删除容器 | 内存删除 |
| SKF_EnumContainer | 枚举容器 | 返回容器名列表 |
| SKF_OpenContainer | 打开容器 | 返回容器句柄 |
| SKF_CloseContainer | 关闭容器 | 释放容器句柄 |

### 5.7 ECC 密码服务（10个）

| 函数 | 功能 | 实现方式 |
|------|------|---------|
| SKF_GenECCKeyPair | 生成 ECC 密钥对 | libsmx sm2::generate_keypair |
| SKF_ImportECCKeyPair | 导入 ECC 加密密钥对 | 解析 ENVELOPEDKEYBLOB，存入容器 |
| SKF_ECCSignData | ECC 签名 | libsmx sm2::sign_message |
| SKF_ECCVerify | ECC 验签 | libsmx sm2::verify_message |
| SKF_ECCExportSessionKey | 导出会话密钥 | SM2 加密随机 SM4 密钥 |
| SKF_ExtECCEncrypt | 外部 ECC 加密 | libsmx sm2::encrypt |
| SKF_ExtECCDecrypt | 外部 ECC 解密 | libsmx sm2::decrypt |
| SKF_ExtECCSign | 外部 ECC 签名 | libsmx sm2::sign_message |
| SKF_ExtECCVerify | 外部 ECC 验签 | libsmx sm2::verify_message |
| SKF_GenerateAgreementDataWithECC | ECC 密钥协商(发起) | stub |
| SKF_GenerateAgreementDataAndKeyWithECC | ECC 密钥协商(响应) | stub |
| SKF_GenerateKeyWithECC | ECC 密钥协商(完成) | stub |
| SKF_ExportPublicKey | 导出容器公钥 | 从容器读取公钥 |
| SKF_ImportCertificate | 导入证书 | 存入容器 |
| SKF_ExportCertificate | 导出证书 | 从容器读取 |

### 5.8 对称密码服务（7个）

| 函数 | 功能 | 实现方式 |
|------|------|---------|
| SKF_SetSymmKey | 设置对称密钥 | 存入会话密钥表 |
| SKF_EncryptInit | 加密初始化 | 保存算法ID + 参数 |
| SKF_Encrypt | 单组加密 | libsmx SM4 加密 |
| SKF_EncryptUpdate | 多组加密更新 | stub（返回不支持） |
| SKF_EncryptFinal | 加密结束 | stub |
| SKF_DecryptInit | 解密初始化 | 保存算法ID + 参数 |
| SKF_Decrypt | 单组解密 | libsmx SM4 解密 |
| SKF_DecryptUpdate | 多组解密更新 | stub |
| SKF_DecryptFinal | 解密结束 | stub |

### 5.9 哈希运算（4个）

| 函数 | 功能 | 实现方式 |
|------|------|---------|
| SKF_DigestInit | 哈希初始化 | 创建 SM3 上下文 |
| SKF_Digest | 单组哈希 | libsmx sm3 |
| SKF_DigestUpdate | 哈希更新 | 累积数据 |
| SKF_DigestFinal | 哈希结束 | 输出摘要 |

### 5.10 RSA 相关（stub）

所有 RSA 接口（SKF_GenRSAKeyPair, SKF_RSASignData, SKF_RSAVerify, SKF_RSAExportSessionKey, SKF_ExtRSAPubKeyOperation, SKF_ExtRSAPriKeyOperation）全部返回 `SAR_NOTSUPPORTYETERR`。

---

## 六、配置文件设计

### 6.1 mock_keys.toml

```toml
# SKF Mock 配置

[device]
name = "MockSKFDevice"
manufacturer = "Mock Manufacturer"
serial = "MOCK-SKF-001"
label = "Test Token"

# 默认应用
[[applications]]
name = "TestApp"
admin_pin = "12345678"
user_pin = "12345678"
admin_pin_retry = 10
user_pin_retry = 10

# 默认容器（在 TestApp 下）
[[applications.containers]]
name = "TestContainer"
# 签名密钥对
sign_private_key = "cc54df687d98e2cac86786f469f04c69b280f19a0eccf8bdf15bfeab778cada0"
sign_public_key_x = "28a446..."
sign_public_key_y = "..."
# 加密密钥对
enc_private_key = "5db59d1f2a8cd51bb570f0689955a4f55e6999a8c1c4635a45bd7770616f0753"
enc_public_key_x = "..."
enc_public_key_y = "..."
# 证书（DER base64）
sign_cert = ""
enc_cert = ""
```

**配置文件查找优先级**（从高到低）：
1. 环境变量 `SKF_MOCK_CONFIG` 指定的路径
2. 当前工作目录 `mock_keys.toml`

---

## 七、开发阶段划分

### 阶段 1：项目骨架搭建
**交付物**：可编译的 Cargo 项目，基本目录结构

- [ ] 1.1 初始化 Cargo 项目，配置 Cargo.toml 依赖（libsmx 0.3, rand, hex, serde, toml, log）
- [ ] 1.2 创建模块目录结构（`ffi/`, `skf_impl/`, `crypto/`, `key_mgr/`, `config/`）
- [ ] 1.3 定义错误码常量（`src/error_code.rs`）
- [ ] 1.4 定义 `#[repr(C)]` 数据结构（`src/types.rs`）
- [ ] 1.5 实现配置文件解析（`src/config/`）

### 阶段 2：设备与应用管理
**交付物**：设备连接/断开、应用 CRUD、PIN 管理

- [ ] 2.1 实现 DeviceContext / Application / Container 内存模型（`src/key_mgr/`）
- [ ] 2.2 实现句柄管理器（AtomicU32 递增 + HashMap）
- [ ] 2.3 实现设备管理 FFI（SKF_EnumDev, SKF_ConnectDev, SKF_DisConnectDev, SKF_GetDevInfo 等）
- [ ] 2.4 实现应用管理 FFI（SKF_CreateApplication, SKF_OpenApplication, SKF_CloseApplication 等）
- [ ] 2.5 实现 PIN 管理 FFI（SKF_VerifyPIN, SKF_ChangePIN, SKF_GetPINInfo, SKF_UnblockPIN）

### 阶段 3：容器与文件管理
**交付物**：容器 CRUD、文件 CRUD

- [ ] 3.1 实现容器管理 FFI（SKF_CreateContainer, SKF_OpenContainer, SKF_CloseContainer 等）
- [ ] 3.2 实现文件管理 FFI（SKF_CreateFile, SKF_ReadFile, SKF_WriteFile 等）
- [ ] 3.3 实现证书导入/导出（SKF_ImportCertificate, SKF_ExportCertificate）
- [ ] 3.4 实现公钥导出（SKF_ExportPublicKey）

### 阶段 4：ECC 密码服务
**交付物**：SM2 签名/验签/加密/解密

- [ ] 4.1 实现 SM2 密钥对生成（SKF_GenECCKeyPair）
- [ ] 4.2 实现 SM2 签名/验签（SKF_ECCSignData, SKF_ECCVerify）
- [ ] 4.3 实现 SM2 外部签名/验签（SKF_ExtECCSign, SKF_ExtECCVerify）
- [ ] 4.4 实现 SM2 外部加密/解密（SKF_ExtECCEncrypt, SKF_ExtECCDecrypt）
- [ ] 4.5 实现会话密钥导出（SKF_ECCExportSessionKey）
- [ ] 4.6 实现 ECC 加密密钥对导入（SKF_ImportECCKeyPair）
- [ ] 4.7 密钥协商接口 stub（返回 SAR_NOTSUPPORTYETERR）

### 阶段 5：对称密码 + 哈希服务
**交付物**：SM4 加密/解密、SM3 哈希

- [ ] 5.1 实�� SM4 对称密钥设置（SKF_SetSymmKey）
- [ ] 5.2 实现 SM4 加解密（SKF_EncryptInit/SKF_Encrypt, SKF_DecryptInit/SKF_Decrypt）
- [ ] 5.3 实现 SM3 哈希（SKF_DigestInit, SKF_Digest, SKF_DigestUpdate, SKF_DigestFinal）
- [ ] 5.4 实现随机数生成（SKF_GenRandom）
- [ ] 5.5 多组加解密 stub（SKF_EncryptUpdate/Final, SKF_DecryptUpdate/Final）

### 阶段 6：Stub 接口 + 集成测试
**交付物**：RSA stub、设备认证 stub、完整测试

- [ ] 6.1 RSA 接口全部 stub（6个函数，返回 SAR_NOTSUPPORTYETERR）
- [ ] 6.2 设备认证 stub（SKF_DevAuth, SKF_ChangeDevAuthKey）
- [ ] 6.3 其余未实现接口 stub（SKF_WaitForDevEvent, SKF_CancelWaitForDevEvent, SKF_GetDevState, SKF_SetLabel）
- [ ] 6.4 编写集成测试（完整调用链）
- [ ] 6.5 编写 README.md

---

## 八、项目目录结构

```
0016-skf-mock/
├── Cargo.toml
├── mock_keys.toml           # 密钥与应用配置
├── README.md
├── projectplan.md
└── src/
    ├── lib.rs               # 库入口，声明模块
    ├── error_code.rs         # SAR_* 错误码常量
    ├── types.rs              # #[repr(C)] 结构体定义
    ├── config/
    │   ├── mod.rs
    │   └── mock_config.rs    # mock_keys.toml 解析
    ├── key_mgr/
    │   ├── mod.rs
    │   ├── context.rs        # DeviceContext / Application / Container
    │   └── handle_mgr.rs     # 句柄管理器
    ├── crypto/
    │   ├── mod.rs
    │   ├── sm2_ops.rs        # SM2 操作 + 公钥格式转换
    │   ├── sm3_ops.rs        # SM3 哈希
    │   └── sm4_ops.rs        # SM4 加解密
    ├── skf_impl/
    │   ├── mod.rs
    │   ├── device.rs         # 设备管理（全局单例 + with_device 守卫）
    │   ├── application.rs    # 应用管理 + PIN 管理
    │   ├── container.rs      # 容器管理 + 证书管理
    │   ├── ecc.rs            # ECC 密码服务
    │   ├── symmetric.rs      # 对称密码服务
    │   └── hash.rs           # 哈希运算
    └── ffi/
        ├── mod.rs
        ├── helpers.rs        # FFI 辅助（指针检查、字符串转换）
        ├── device_ffi.rs     # 设备管理 extern "C"
        ├── app_ffi.rs        # 应用管理 extern "C"
        ├── container_ffi.rs  # 容器管理 extern "C"
        ├── crypto_ffi.rs     # 密码服务 extern "C"
        └── stub_ffi.rs       # RSA 等 stub extern "C"
```

---

## 九、关键实现细节

### 9.1 公钥格式转换

libsmx 使用 65 字节 `04||x(32)||y(32)`，SKF 规范使用 `ECCPUBLICKEYBLOB { BitLen=256, XCoordinate[64], YCoordinate[64] }`（各 64 字节，右对齐大端补零）。

```rust
fn pub_key_to_blob(pk_65: &[u8; 65]) -> ECCPUBLICKEYBLOB {
    let mut blob = ECCPUBLICKEYBLOB { BitLen: 256, ..Default::default() };
    blob.XCoordinate[32..].copy_from_slice(&pk_65[1..33]);
    blob.YCoordinate[32..].copy_from_slice(&pk_65[33..65]);
    blob
}

fn blob_to_pub_key(blob: &ECCPUBLICKEYBLOB) -> [u8; 65] {
    let mut pk = [0u8; 65];
    pk[0] = 0x04;
    pk[1..33].copy_from_slice(&blob.XCoordinate[32..]);
    pk[33..65].copy_from_slice(&blob.YCoordinate[32..]);
    pk
}
```

### 9.2 签名格式转换

libsmx 输出 64 字节 `r(32)||s(32)`，SKF 使用 `ECCSIGNATUREBLOB { r[64], s[64] }`（各 64 字节右对齐）。

### 9.3 密文格式转换

libsmx 输出 `C1(65)||C3(32)||C2(变长)`，SKF 使用 `ECCCIPHERBLOB { XCoordinate[64], YCoordinate[64], HASH[32], CipherLen, Cipher[] }`。

### 9.4 PIN 管理

- 管理员 PIN（ADMIN_TYPE=0）：可修改用户 PIN、解锁用户 PIN
- 用户 PIN（USER_TYPE=1）：使用密码服务的前置条件
- 重试次数：验证失败递减，归零则锁定
- Mock 中 PIN 值存于配置文件，运行时可修改（仅内存）

### 9.5 SM4 加解密模式

支持 ECB 和 CBC 两种模式（libsmx 提供）。其余模式（CFB/OFB/CTR）返回 SAR_NOTSUPPORTYETERR。

---

## 十、Cargo.toml 核心依赖

```toml
[package]
name = "skf-mock"
version = "0.1.0"
edition = "2021"

[lib]
name = "skf_mock"
crate-type = ["cdylib", "rlib"]

[dependencies]
libsmx = "0.3"
rand = "0.8"
hex = "0.4"
serde = { version = "1", features = ["derive"] }
toml = "0.8"
log = "0.4"
env_logger = "0.11"

[dev-dependencies]
hex = "0.4"
```

---

## 十一、与 0018-sdk-mock 的异同

| 维度 | 0018 (SDF) | 0016 (SKF) |
|------|-----------|-----------|
| 层次模型 | 设备 → 会话 | 设备 → 应用 → 容器 |
| 密钥管理 | 按索引（1-based） | 按容器名 |
| 句柄类型 | DeviceHandle + SessionHandle | DeviceHandle + AppHandle + ContainerHandle |
| PIN 管理 | 无 | 有（管理员 PIN + 用户 PIN） |
| 文件管理 | 有 | 有 |
| 证书管理 | 无 | 有（容器内） |
| 密钥对组织 | 按索引分散 | 签名+加密成对放容器里 |
| 算法库 | gm-sdk-rs | libsmx 0.3 |
| 密钥协商 | 实现 | stub |

**主要差异**：SKF 多了一层 Application 抽象和 PIN 访问控制，密钥按容器组织而非按索引。架构模式（全局单例 + 句柄映射 + FFI 分层）保持一致。

---

## 十二、Review — 实现总结

### 完成情况

所有 6 个阶段已全部完成，`cargo check` 零错误（170 个 warning 全为 C 风格命名约定，FFI 强制保留）。

### 目录结构（最终）

```
0016-skf-mock/
├── Cargo.toml
├── projectplan.md
└── src/
    ├── lib.rs                      # 模块声明 + FFI 引用
    ├── error_code.rs               # SAR_* 错误码 + 算法 ID 常量
    ├── types.rs                    # 所有 #[repr(C)] SKF 数据结构
    ├── config/
    │   ├── mod.rs
    │   └── mock_config.rs          # MockConfig::load() 解析 TOML
    ├── key_mgr/
    │   ├── mod.rs
    │   └── context.rs              # DeviceContext + 所有句柄类型
    ├── crypto/
    │   ├── mod.rs
    │   ├── sm2_ops.rs              # SM2 操作 + 格式转换
    │   ├── sm3_ops.rs              # SM3 操作 + Sm3State
    │   └── sm4_ops.rs              # SM4 操作 + PKCS7 padding
    ├── skf_impl/
    │   ├── mod.rs
    │   ├── device.rs               # with_device() + 设备级操作
    │   ├── application.rs          # 应用/PIN 管理
    │   ├── container.rs            # 容器/文件/证书管理
    │   ├── ecc.rs                  # ECC 密钥对 + SM2 签名/加密
    │   ├── symmetric.rs            # SM4 对称加解密
    │   └── hash.rs                 # SM3 哈希
    └── ffi/
        ├── mod.rs
        ├── helpers.rs              # 占位（供将来共享工具）
        ├── device_ffi.rs           # SKF_EnumDev / SKF_ConnectDev 等
        ├── app_ffi.rs              # SKF_CreateApplication / SKF_VerifyPIN 等
        ├── container_ffi.rs        # SKF_CreateContainer / SKF_ECCSignData 等
        ├── crypto_ffi.rs           # SKF_SetSymmKey / SKF_DigestInit 等
        └── stub_ffi.rs             # RSA / 密钥协商（全部返回不支持）
```

### 关键设计决策

1. **全局单例**：`static DEVICE_CTX: OnceLock<Mutex<Option<DeviceContext>>>` + `with_device()` 保护所有访问
2. **句柄编码**：u32 值直接 cast 为 `*mut c_void`，4 类句柄不同起始值（0x1001/0x2001/0x3001/0x4001）
3. **PKCS7 手工实现**：libsmx SM4 不含填充，自行实现 `pkcs7_pad/unpad`
4. **SM3 缓冲模式**：`Sm3State` 缓冲数据，在 DigestFinal 一次性计算（libsmx 无增量 API）
5. **Z 值计算**：`DigestInit` 传入公钥时预计算 Z 值写入缓冲头部，`DigestUpdate` 直接追加消息
6. **SKF_ImportECCKeyPair 简化**：信封私钥解密需要容器本身的加密私钥，Mock 中仅存公钥（零私钥占位）
7. **ECCCIPHERBLOB 固定长度**：规范中 `Cipher[1]` 为变长，Mock 定为 `[u8; 512]`（最大明文限制）

---

## 十三、MCP Server 集成（2026-04-22）

### 13.1 目标

为 skf-mock 添加 MCP Server 二进制可执行文件，让 Claude/Cursor 等 LLM 通过 Streamable HTTP 直接调用 SM2/SM3/SM4 国密能力（模拟终端 USB Key）。

### 13.2 完成情况

- [x] 修改 `Cargo.toml`：保留 `[lib]` cdylib+rlib，新增 `[[bin]] skf-mcp`，添加 rmcp/axum/tokio/clap/tracing 等依赖
- [x] 新建 `src/bin/mcp_server.rs`：单文件实现 12 个 MCP Tool + ServerHandler
- [x] `cargo check --bin skf-mcp` 零错误

### 13.3 已实现的 12 个 MCP Tool

| 工具名 | 对应 SKF API | 说明 |
|-------|-------------|------|
| `skf_device_info` | SKF_GetDevInfo | 获取设备状态和默认句柄 |
| `skf_open_app` | SKF_OpenApplication + SKF_VerifyPIN | 打开应用验证 PIN，返回句柄 |
| `skf_list_containers` | SKF_EnumContainer | 列出容器名称 |
| `skf_gen_ecc_keypair_tool` | SKF_GenECCKeyPair | 生成 SM2 密钥对 |
| `skf_import_cert` | SKF_ImportCertificate | 导入证书 DER |
| `skf_export_cert` | SKF_ExportCertificate/PublicKey | 导出证书或公钥 |
| `skf_sm2_sign` | SKF_ECCSignData | 使用容器签名私钥签名 |
| `skf_sm2_verify` | SKF_ECCVerify | 使用外部公钥验签 |
| `skf_sm2_ext_sign` | SKF_ExtECCSign | 外部私钥签名 |
| `skf_sm2_ext_verify` | SKF_ExtECCVerify | 外部公钥验签 |
| `skf_sm4_crypt` | SKF_SetSymmKey + SKF_Encrypt/Decrypt | SM4 加解密（CBC/ECB）|
| `skf_sm3_digest` | sm3_ops | SM3 摘要（可选 Z 值前缀）|

### 13.4 关键设计决策

1. **预初始化句柄**：启动时调用 `init_skf_device()` 连接设备、打开第一个应用/容器，把句柄存在 `SkfMcpServer` struct，LLM 调用 `skf_device_info` 即可获取默认 `container_handle`，无需手动管理句柄生命周期
2. **参数约定**：所有输入输出均 hex 编码；错误返回 `{"error":"描述（错误码: 0xXXXXXXXX）"}`
3. **SM3 Z 值**：`skf_sm3_digest` 提供 `public_key_hex` 时直接调用底层 `sm3_ops::sm2_z_value` + `sm3_ops::sm3_digest`，避免 FFI 句柄管理复杂性
4. **SM4 pre_hashed**：`skf_sm2_sign` 的 `pre_hashed=true` 路径从容器取出私钥后直接调用底层 `sm2_ops::sm2_sign`，绕过 SKF 的自动 Z 值处理
5. **Streamable HTTP**：使用 `StreamableHttpServerConfig::with_stateful_mode(false)` + `LocalSessionManager`，适合本地 mock 场景

### 13.5 启动方式

```bash
# 构建
cargo build --bin skf-mcp --release

# 启动（默认端口 16000）
./target/release/skf-mcp

# 指定端口
./target/release/skf-mcp --port 18000

# MCP 端点
# POST http://localhost:16000/mcp
```

### 13.6 Claude/Cursor MCP 配置示例

```json
{
  "mcpServers": {
    "skf-mock": {
      "url": "http://localhost:16000/mcp"
    }
  }
}
```

