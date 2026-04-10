# skf-mock 作为 mPlugin 底层 SKF DLL 使用指南

## 1. 架构概述

mPlugin 是龙脉科技提供的浏览器插件替代方案，采用**本地 HTTP 服务**架构：

```
浏览器 JS (SOF_* API)
    │  HTTP POST JSON
    │  ws://127.0.0.1:51235
    ▼
mPlugin 本地服务（中间件）
    │  LoadLibrary / dlopen
    │  SKF_* ABI (cdylib)
    ▼
SKF 底层 DLL（硬件驱动 或 skf-mock）
```

skf-mock 实现 GM/T 0016-2012 SKF 接口规范，可作为 SKF 底层 DLL 直接被 mPlugin 加载，**无需修改 JS 代码**。

---

## 2. 构建 skf-mock

```bash
# Windows（生成 skf_mock.dll）
cargo build --release
# 输出：target/release/skf_mock.dll

# Linux（生成 libskf_mock.so）
cargo build --release
# 输出：target/release/libskf_mock.so
```

---

## 3. 让 mPlugin 加载 skf-mock

mPlugin 通过 `SOF_LoadLibrary` 指定要加载的底层 DLL 名称。

### 方式 A：JS 直接指定（推荐用于开发测试）

```js
// 加载 skf-mock 作为底层 DLL
SOF_LoadLibrary("skf_mock.dll");         // Windows
SOF_LoadLibrary("libskf_mock.so");       // Linux
```

确保 DLL 文件与 mPlugin 可执行文件在同一目录，或位于系统 `PATH` / `LD_LIBRARY_PATH` 中。

### 方式 B：重命名/覆盖原有 DLL（用于替换测试）

将 skf-mock 输出文件重命名为 mPlugin 默认加载的 DLL 名称：

```bash
# Windows
copy target\release\skf_mock.dll  <mPlugin目录>\mtoken_gm3000.dll

# Linux
cp target/release/libskf_mock.so  <mPlugin目录>/libgm3000.1.0.so
```

---

## 4. 配置预置密钥

skf-mock 通过 TOML 配置文件预置设备/应用/容器/密钥信息。

**查找顺序**：`SKF_MOCK_CONFIG` 环境变量 → `./mock_keys.toml` → 内置默认值

```toml
# mock_keys.toml 示例

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
  sign_private_key = "your_32byte_hex_privkey"
  sign_public_key_x = "your_32byte_hex_pubkey_x"
  sign_public_key_y = "your_32byte_hex_pubkey_y"
  # DER 格式证书 base64（支持换行）
  sign_cert = """
  MIIB...（base64 DER）
  """
```

启动 mPlugin 时设置环境变量：

```bash
# Linux
SKF_MOCK_CONFIG=/path/to/mock_keys.toml ./mPlugin

# Windows (PowerShell)
$env:SKF_MOCK_CONFIG = "C:\path\to\mock_keys.toml"
.\mPlugin.exe
```

---

## 5. SOF_* 与 SKF_* 接口映射

下表列出 mPlugin JS API 与底层 SKF DLL 调用的对应关系，以及 skf-mock 的支持情况。

### 5.1 设备与会话

| JS 接口 | SKF 调用 | skf-mock 状态 |
|---------|---------|--------------|
| `SOF_LoadLibrary(dllName)` | `SKF_ConnectDev` | ✅ 已实现 |
| `SOF_FreeLibrary()` | `SKF_DisConnectDev` | ✅ 已实现 |
| `SOF_GetDeviceType()` | `SKF_GetDevInfo` | ✅ 已实现 |
| `SOF_GetDeviceList()` | `SKF_EnumDev` | ✅ 已实现 |
| `SOF_GetDeviceCount()` | `SKF_EnumDev` | ✅ 已实现 |
| `SOF_GetCertificateCount()` | `SKF_EnumApplication` + 枚举容器 | ✅ 已实现 |

### 5.2 PIN 与应用管理

| JS 接口 | SKF 调用 | skf-mock 状态 |
|---------|---------|--------------|
| `SOF_Login(pin)` | `SKF_VerifyPIN(USER_TYPE, ...)` | ✅ 已实现 |
| `SOF_Logout()` | 内部状态清除（mPlugin 处理） | — mPlugin 内部 |
| `SOF_ChangePIN(oldPin, newPin)` | `SKF_ChangePIN` | ✅ 已实现 |
| `SOF_GetPinRetryCount()` | `SKF_GetPINInfo` | ✅ 已实现 |

### 5.3 证书操作

| JS 接口 | SKF 调用 | skf-mock 状态 |
|---------|---------|--------------|
| `SOF_GetCertificateByIndex(idx)` | `SKF_ExportCertificate` | ✅ 已实现 |
| `SOF_GetCertInfo(cert, field)` | X.509 解析（mPlugin 内部）| — mPlugin 内部 |
| `SOF_VerifyCertificate(cert)` | 证书链验证（mPlugin 内部）| — mPlugin 内部 |
| `SOF_GetUserList()` | 枚举应用/容器 | ✅ 已实现 |

> **注**：证书字段解析、证书链验证、根证书校验均由 mPlugin 内部完成，不调用 SKF DLL。

### 5.4 SM2 签名

| JS 接口 | SKF 调用 | skf-mock 状态 |
|---------|---------|--------------|
| `SOF_SignData(certIdx, data)` | `SKF_ECCSignData(hCnt, data, len, &sig)` | ✅ 已实现 |
| `SOF_VerifySignedData(cert, data, sig)` | `SKF_ECCVerify` | ✅ 已实现 |
| `SOF_SignDataWithCert(certDer, data)` | `SKF_ExtECCSign` | ✅ 已实现 |

签名流程：
1. mPlugin 查找证书对应容器 → 获取 `HCONTAINER`
2. mPlugin 计算 `Z = SM3(entlen||uid||curve_params||pubkey)` 并预处理消息
3. 调用 `SKF_ECCSignData`，skf-mock 返回 `ECCSIGNATUREBLOB`
4. mPlugin 将签名编码为 Base64/DER 返回 JS

### 5.5 SM2 加解密

| JS 接口 | SKF 调用 | skf-mock 状态 |
|---------|---------|--------------|
| `SOF_Encrypt(certIdx, data)` | `SKF_ExtECCEncrypt(hDev, &pubBlob, data, len, &cipherBlob)` | ✅ 已实现 |
| `SOF_Decrypt(certIdx, data)` | `SKF_ECCDecrypt(hCnt, &cipherBlob, out, &outLen)` | ✅ 已实现 |

### 5.6 SM4 对称加解密

| JS 接口 | SKF 调用 | skf-mock 状态 |
|---------|---------|--------------|
| `SOF_EncryptData(key, data)` | `SKF_SetSymmKey` + `SKF_EncryptInit` + `SKF_Encrypt` | ✅ 已实现 |
| `SOF_DecryptData(key, data)` | `SKF_SetSymmKey` + `SKF_DecryptInit` + `SKF_Decrypt` | ✅ 已实现 |

### 5.7 SM3 哈希与 PKCS7

| JS 接口 | SKF 调用 | skf-mock 状态 |
|---------|---------|--------------|
| `SOF_DigestData(data)` | `SKF_DigestInit` + `SKF_Digest` | ✅ 已实现 |
| `SOF_SignPKCS7(certIdx, data)` | PKCS7/CMS 构造（mPlugin 内部）+ `SKF_ECCSignData` | ✅ SKF 部分已实现 |
| `SOF_VerifyPKCS7(pkcs7, data)` | PKCS7 解析（mPlugin 内部）+ `SKF_ECCVerify` | ✅ SKF 部分已实现 |

> **注**：PKCS7/CMS 结构的组装与解析完全由 mPlugin 内部完成（使用 OpenSSL 或内置 ASN.1 库）。skf-mock 只需提供底层签名/验签接口。

### 5.8 mPlugin 内部处理（不依赖 SKF DLL）

以下功能完全在 mPlugin 内部实现，skf-mock **无需**提供支持：

| 功能 | 说明 |
|------|------|
| CSR 生成 (`SOF_GenCSR`) | PKCS#10 ASN.1 构造，mPlugin 内部 |
| 证书字段解析 | X.509 DER 解析，mPlugin 内部 |
| 证书链验证 | 根证书列表校验，mPlugin 内部 |
| 指纹识别 (`SOF_GetFingerprint`) | 硬件指纹模块，不经 SKF |
| 二维码 (`SOF_ScanQRCode`) | 摄像头/图像处理，不经 SKF |
| Base64/十六进制编解码 | mPlugin 工具函数 |

---

## 6. 算法 ID 对照

**重要**：GM/T 0016（SKF）与 GM/T 0018（SDF）使用不同的算法 ID 体系。mPlugin JS 端和 skf-mock 均遵循 GM/T 0016 值。

| 常量 | GM/T 0016 SKF 值 | GM/T 0018 SDF 值（错误！）|
|------|-----------------|----------------------|
| SGD_SM2_1（签名）| `0x00020100` | `0x00020200` |
| SGD_SM2_2（密钥交换）| `0x00020200` | — |
| SGD_SM2_3（加密）| `0x00020400` | `0x00020800` |
| SGD_SM3 | `0x00000001` | `0x00000001` |
| SGD_SM4_ECB | `0x00000401` | `0x00000401` |
| SGD_SM4_CBC | `0x00000402` | `0x00000402` |

---

## 7. 已知限制

| 接口 | 状态 | 说明 |
|------|------|------|
| RSA 全套 | ❌ 桩（返回 SAR_NOTSUPPORTYETERR）| mPlugin 国密场景不需要 |
| ECC 密钥协商 (`SKF_GenerateAgreementDataWithECC` 等) | ❌ 桩 | 仅 TLS 等场景用到 |
| MAC (`SKF_MACInit/MAC`) | ❌ 桩 | 基本不被 mPlugin 使用 |
| `SKF_ImportECCKeyPair` 私钥 | ⚠️ 简化 | 仅存公钥，私钥全零占位 |
| 多设备并发 | ❌ 不支持 | 全局单例，仅支持单设备 |

---

## 8. 调试技巧

```bash
# 开启详细日志（查看 SKF 函数调用和参数）
RUST_LOG=debug SKF_MOCK_CONFIG=./mock_keys.toml ./mPlugin

# 单独运行 skf-mock 集成测试验证功能
cargo test -- --nocapture

# 验证特定接口
cargo test test_sm2_sign_verify -- --nocapture
```

日志示例：
```
[DEBUG skf_mock] SKF_ConnectDev: dev=MockSKFDevice
[DEBUG skf_mock] SKF_OpenApplication: CryptoApp handle=0x00001001
[DEBUG skf_mock] SKF_ECCSignData: hCnt=0x00002001 msgLen=32
```
