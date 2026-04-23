# skf-mock — GM/T 0016-2012 Smart Cryptographic Key Interface

> Part of [gm-agent-stack](../gm-agent-stack/) — AI-native GM cryptography toolkit

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![GM/T](https://img.shields.io/badge/GM%2FT-0016--2012-red.svg)](docs/)
[![MCP](https://img.shields.io/badge/MCP-Streamable%20HTTP-green.svg)](http://localhost:16000/mcp)

Pure-software mock of a GM/T 0016-2012 Smart Cryptographic Key (USB dongle/token). Ships as a **dynamic library** for FFI and a standalone **MCP Server** binary for AI agent use.

纯软件实现的 GM/T 0016-2012 智能密码钥匙接口，提供动态库和 MCP Server，无需真实 USB Key 硬件。

---

## Quick Start / 快速开始

### MCP Server (for AI agents / 供 AI Agent)

```bash
cargo build --release --bin skf-mcp
./target/release/skf-mcp --port 16000
claude mcp add skf-mock --url http://localhost:16000/mcp
```

### Dynamic Library (for C programs / 供 C 程序链接)

```bash
cargo build --release
# → target/release/libskf_mock.so
```

```c
#include "skf.h"
DEVHANDLE hDev;  HAPPLICATION hApp;  HCONTAINER hCon;
SKF_ConnectDev(L"SKF-MOCK-001", &hDev);
SKF_OpenApplication(hDev, L"DefaultApp", &hApp);
SKF_VerifyPIN(hApp, USER_TYPE, L"12345678", &retry);
SKF_OpenContainer(hApp, L"SignContainer", &hCon);
// SM2 sign, verify, SM4 encrypt, SM3 hash...
```

## MCP Tools / MCP 工具

| Tool | Description |
|------|-------------|
| `skf_device_info` | Enumerate devices and get info |
| `skf_open_app` | Open application + verify PIN + open container |
| `skf_list_containers` | List containers |
| `skf_gen_keypair` | Generate SM2 key pair in container |
| `skf_import_cert` | Import certificate |
| `skf_export_cert` | Export certificate or public key |
| `skf_sm2_sign` | SM2 sign (with Z-value pre-processing) |
| `skf_sm2_verify` | SM2 verify |
| `skf_sm2_ext_sign` | SM2 sign with external private key hex |
| `skf_sm2_ext_verify` | SM2 verify with external public key hex |
| `skf_sm4_crypt` | SM4 encrypt/decrypt (ECB/CBC) |
| `skf_sm3_digest` | SM3 hash (with optional Z-value) |
| `skf_manage_pin` | PIN change/unblock/query retry count |

## Device Model / 设备层级

```
Device (设备) — SKF-MOCK-001
└── Application (应用, PIN protected) — DefaultApp / PIN: 12345678
    └── Container (容器)
        ├── Sign Key Pair (签名密钥对)
        └── Enc  Key Pair (加密密钥对)
```

> ⚠️ **For development and testing only. Not for production use.**  
> ⚠️ **仅供学习和开发测试使用，严禁用于生产环境。**
