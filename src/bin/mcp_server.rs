/// SKF MCP Server — GM/T 0016-2012 国密智能密码钥匙工具集（MCP Streamable HTTP 传输）
///
/// 提供 12 个 MCP Tool，让 Claude/Cursor 等 LLM 可直接调用 SM2/SM3/SM4 国密能力，
/// 模拟终端 USB Key 的密码运算接口，无需真实硬件。
///
/// 启动方式：skf-mcp --port 16000
///
/// 工具端点：POST http://localhost:16000/mcp
use clap::Parser;
use rmcp::{
    ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router,
};
use tracing::info;

// 引入 skf-mock 库的所有公开模块
// Reason: 二进制 crate 通过 rlib 直接调用 lib 的业务层，避免重复实现
use skf_mock::{
    crypto::{sm2_ops, sm3_ops},
    error_code::SAR_OK,
    skf_impl::{
        device::with_device,
        application::{skf_open_application, skf_verify_pin},
        container::{skf_create_container, skf_open_container},
        ecc::{skf_gen_ecc_keypair, skf_ecc_sign_data, skf_ecc_verify,
               skf_ext_ecc_sign, skf_ext_ecc_verify},
        symmetric::{skf_set_symm_key, skf_encrypt_init, skf_encrypt, skf_decrypt_init, skf_decrypt},
    },
    types::{ECCPUBLICKEYBLOB, ECCSIGNATUREBLOB, BLOCKCIPHERPARAM},
    error_code::{SGD_SM2_1, SGD_SM2_3, SGD_SM4_CBC, SGD_SM4_ECB, USER_TYPE},
};

// ── CLI 参数 ─────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    version,
    about = "SKF MCP Server — GM/T 0016-2012 国密智能密码钥匙 MCP 接口"
)]
struct Cli {
    /// MCP Server 监听端口（默认 16000）
    #[arg(long, default_value_t = 16000)]
    port: u16,

    /// 运行模式（保留参数，仅 mcp 有效）
    #[arg(long, default_value = "both")]
    mode: String,
}

// ── 参数结构 ─────────────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct OpenAppParams {
    #[schemars(description = "应用名称，默认 \"DEFAULT\"")]
    pub app_name: Option<String>,
    #[schemars(description = "用户 PIN，默认 \"12345678\"")]
    pub pin: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ListContainersParams {
    #[schemars(description = "应用句柄（skf_open_app 返回的 app_handle）")]
    pub app_handle: u32,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct GenKeypairParams {
    #[schemars(description = "容器句柄（skf_open_app 返回的 container_handle）")]
    pub container_handle: u32,
    #[schemars(description = "true=生成签名密钥，false=生成加密密钥")]
    pub sign_flag: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ImportCertParams {
    #[schemars(description = "容器句柄")]
    pub container_handle: u32,
    #[schemars(description = "证书 DER 的 hex 编码")]
    pub cert_der_hex: String,
    #[schemars(description = "true=签名证书，false=加密证书")]
    pub sign_flag: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ExportCertParams {
    #[schemars(description = "容器句柄")]
    pub container_handle: u32,
    #[schemars(description = "true=导出签名证书/公钥，false=导出加密证书/公钥")]
    pub sign_flag: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct Sm2SignParams {
    #[schemars(description = "容器句柄（使用容器内签名私钥）")]
    pub container_handle: u32,
    #[schemars(description = "待签名数据的 hex 编码")]
    pub data_hex: String,
    #[schemars(
        description = "false（默认）：自动对数据计算 SM3(Z||data) 后签名；true：数据已是 32 字节摘要，直接签名"
    )]
    pub pre_hashed: Option<bool>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct Sm2VerifyParams {
    #[schemars(description = "SM2 公钥点 04||x||y（65字节=130 hex）")]
    pub public_key_hex: String,
    #[schemars(description = "原始数据 hex（与签名时使用的相同原文）")]
    pub data_hex: String,
    #[schemars(description = "签名 r||s（64字节=128 hex）")]
    pub signature_hex: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct Sm2ExtSignParams {
    #[schemars(description = "SM2 私钥 hex（32字节=64 hex）")]
    pub private_key_hex: String,
    #[schemars(description = "待签名数据 hex")]
    pub data_hex: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct Sm2ExtVerifyParams {
    #[schemars(description = "SM2 公钥点 04||x||y（65字节=130 hex）")]
    pub public_key_hex: String,
    #[schemars(description = "原始数据 hex")]
    pub data_hex: String,
    #[schemars(description = "签名 r||s（64字节=128 hex）")]
    pub signature_hex: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct Sm4CryptParams {
    #[schemars(description = "操作：\"encrypt\" 或 \"decrypt\"")]
    pub action: String,
    #[schemars(description = "SM4 密钥 hex（16字节=32 hex）")]
    pub key_hex: String,
    #[schemars(
        description = "IV hex（16字节=32 hex）；action=encrypt/decrypt CBC 模式时必填；若为 ECB 模式可传 16字节全零"
    )]
    pub iv_hex: String,
    #[schemars(description = "待加密/解密数据 hex")]
    pub data_hex: String,
    #[schemars(description = "加密模式：\"cbc\"（默认）或 \"ecb\"")]
    pub mode: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct Sm3DigestParams {
    #[schemars(description = "待摘要数据 hex")]
    pub data_hex: String,
    #[schemars(
        description = "可选。SM2 公钥 04||x||y（65字节）hex。提供后先计算 Z 值与消息拼接后再摘要（SM2 签名前置步骤）"
    )]
    pub public_key_hex: Option<String>,
}

// ── MCP Server 结构体 ─────────────────────────────────────────────────────────

/// SKF MCP Server 主结构
/// Reason: 启动时预连接设备并打开默认应用/容器，把句柄存在 struct 里，
/// 避免每次 tool 调用时要求 LLM 管理句柄生命周期
#[derive(Debug, Clone)]
pub struct SkfMcpServer {
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
    /// 默认容器句柄（预初始化，用于签名/加密等需要容器的操作）
    default_container_handle: u32,
    /// 默认应用句柄
    default_app_handle: u32,
}

impl SkfMcpServer {
    pub fn new(default_app_handle: u32, default_container_handle: u32) -> Self {
        Self {
            tool_router: Self::tool_router(),
            default_app_handle,
            default_container_handle,
        }
    }
}

// ── Tool 实现 ─────────────────────────────────────────────────────────────────

#[tool_router]
impl SkfMcpServer {
    /// 工具 1：查询 SKF 模拟设备信息
    #[tool(
        description = "列出并连接 SKF 模拟设备，获取设备基本信息（型号、序列号等）。\
                       返回 JSON：{\"device_name\":\"SKF_MOCK\",\"status\":\"connected\",\
                       \"default_app_handle\":...,\"default_container_handle\":...}"
    )]
    async fn skf_device_info(&self, _params: Parameters<serde_json::Value>) -> String {
        // 从全局设备上下文取设备信息
        let result = with_device(|res| match res {
            Err(_) => serde_json::json!({
                "error": "设备未连接，请确认 skf-mock 库已正确初始化"
            }),
            Ok(ctx) => serde_json::json!({
                "device_name": ctx.mock_cfg.device.name,
                "manufacturer": ctx.mock_cfg.device.manufacturer,
                "serial": ctx.mock_cfg.device.serial,
                "status": "connected",
                "default_app_handle": self.default_app_handle,
                "default_container_handle": self.default_container_handle,
                "applications": ctx.applications.keys().cloned().collect::<Vec<_>>()
            }),
        });
        result.to_string()
    }

    /// 工具 2：打开应用并验证 PIN
    #[tool(
        description = "打开 SKF 应用并验证用户 PIN（对应 SKF_OpenApplication + SKF_VerifyPIN）。\
                       返回 JSON：{\"app_handle\":...,\"container_handle\":...,\"remaining_retry\":...}。\
                       若使用默认应用无需调用此工具，直接使用 skf_device_info 返回的 default_container_handle。"
    )]
    async fn skf_open_app(&self, Parameters(p): Parameters<OpenAppParams>) -> String {
        let app_name = p.app_name.unwrap_or_else(|| "DEFAULT".to_string());
        let pin = p.pin.unwrap_or_else(|| "12345678".to_string());

        // 打开应用
        let mut app_handle_raw: *mut std::os::raw::c_void = std::ptr::null_mut();
        let app_name_c = match std::ffi::CString::new(app_name.clone()) {
            Ok(s) => s,
            Err(e) => return err_json(&format!("应用名包含非法字符: {e}")),
        };
        let rc = skf_open_application(
            1usize as *mut _,  // 设备句柄固定为 1
            app_name_c.as_ptr(),
            &mut app_handle_raw,
        );
        if rc != SAR_OK {
            return err_json(&format!(
                "SKF_OpenApplication 失败，应用名=\"{app_name}\"（错误码: {rc:#010x}）"
            ));
        }
        let app_handle = app_handle_raw as usize as u32;

        // 验证用户 PIN
        let pin_c = match std::ffi::CString::new(pin) {
            Ok(s) => s,
            Err(e) => return err_json(&format!("PIN 包含非法字符: {e}")),
        };
        let mut remaining: u32 = 0;
        let rc = skf_verify_pin(
            app_handle_raw,
            USER_TYPE,
            pin_c.as_ptr(),
            &mut remaining,
        );
        if rc != SAR_OK {
            return err_json(&format!(
                "SKF_VerifyPIN 失败，剩余重试次数 {remaining}（错误码: {rc:#010x}）"
            ));
        }

        // 打开默认容器（"DEFAULT"）
        let con_name = std::ffi::CString::new("DEFAULT").unwrap();
        let mut con_handle_raw: *mut std::os::raw::c_void = std::ptr::null_mut();
        let rc = skf_open_container(app_handle_raw, con_name.as_ptr(), &mut con_handle_raw);
        let container_handle = if rc == SAR_OK {
            con_handle_raw as usize as u32
        } else {
            // 容器不存在时尝试创建
            let rc2 = skf_create_container(app_handle_raw, con_name.as_ptr(), &mut con_handle_raw);
            if rc2 == SAR_OK {
                con_handle_raw as usize as u32
            } else {
                0
            }
        };

        serde_json::json!({
            "app_handle": app_handle,
            "container_handle": container_handle,
            "remaining_retry": remaining
        })
        .to_string()
    }

    /// 工具 3：列出应用下的容器
    #[tool(
        description = "列出应用下所有容器名称（对应 SKF_EnumContainer）。\
                       返回 JSON：{\"containers\":[\"DEFAULT\",...]}"
    )]
    async fn skf_list_containers(&self, Parameters(p): Parameters<ListContainersParams>) -> String {
        let result = with_device(|res| match res {
            Err(e) => serde_json::json!({"error": format!("设备未连接（错误码: {e:#010x}）")}),
            Ok(ctx) => {
                let app_name = match ctx.app_handles.get(&p.app_handle) {
                    Some(n) => n.clone(),
                    None => {
                        return serde_json::json!({
                            "error": format!("应用句柄 {} 无效", p.app_handle)
                        })
                    }
                };
                let app = match ctx.applications.get(&app_name) {
                    Some(a) => a,
                    None => return serde_json::json!({"error": "应用不存在"}),
                };
                let names: Vec<String> = app.containers.keys().cloned().collect();
                serde_json::json!({"containers": names})
            }
        });
        result.to_string()
    }

    /// 工具 4：在容器中生成 SM2 密钥对
    #[tool(
        description = "在容器中生成 SM2 密钥对（SKF_GenECCKeyPair）。\
                       sign_flag=true 生成签名密钥对，sign_flag=false 生成加密密钥对。\
                       返回 JSON：{\"public_key_hex\":\"04...\",\"container_handle\":...}"
    )]
    async fn skf_gen_ecc_keypair_tool(
        &self,
        Parameters(p): Parameters<GenKeypairParams>,
    ) -> String {
        let alg_id = if p.sign_flag { SGD_SM2_1 } else { SGD_SM2_3 };
        let h_container = p.container_handle as usize as *mut std::os::raw::c_void;
        let mut blob = ECCPUBLICKEYBLOB::default();

        let rc = skf_gen_ecc_keypair(h_container, alg_id, &mut blob);
        if rc != SAR_OK {
            return err_json(&format!("SKF_GenECCKeyPair 失败（错误码: {rc:#010x}）"));
        }

        // 将 ECCPUBLICKEYBLOB 转换为 65 字节公钥 hex
        let pub_key = sm2_ops::blob_to_pub_key(&blob);
        serde_json::json!({
            "public_key_hex": hex::encode(&pub_key),
            "container_handle": p.container_handle
        })
        .to_string()
    }

    /// 工具 5：向容器导入证书
    #[tool(
        description = "向容器导入证书 DER（SKF_ImportCertificate）。\
                       sign_flag=true 导入签名证书，false 导入加密证书。\
                       返回 JSON：{\"success\":true}"
    )]
    async fn skf_import_cert(&self, Parameters(p): Parameters<ImportCertParams>) -> String {
        let cert_der = match hex::decode(&p.cert_der_hex) {
            Ok(d) => d,
            Err(e) => return err_json(&format!("cert_der_hex 解码失败: {e}")),
        };
        let h_container = p.container_handle as usize as *mut std::os::raw::c_void;
        let sign_flag: i32 = if p.sign_flag { 1 } else { 0 };

        use skf_mock::skf_impl::container::skf_import_certificate;
        let rc = skf_import_certificate(h_container, sign_flag, cert_der.as_ptr(), cert_der.len() as u32);
        if rc != SAR_OK {
            return err_json(&format!("SKF_ImportCertificate 失败（错误码: {rc:#010x}）"));
        }
        serde_json::json!({"success": true}).to_string()
    }

    /// 工具 6：从容器导出证书或公钥
    #[tool(
        description = "从容器导出证书 DER 或 ECC 公钥（SKF_ExportCertificate / SKF_ExportPublicKey）。\
                       有证书时返回 {\"cert_der_hex\":\"...\"}；无证书但有密钥对时返回 {\"public_key_hex\":\"04...\"}。"
    )]
    async fn skf_export_cert(&self, Parameters(p): Parameters<ExportCertParams>) -> String {
        let h_container = p.container_handle as usize as *mut std::os::raw::c_void;
        let sign_flag: i32 = if p.sign_flag { 1 } else { 0 };

        // 先尝试导出证书
        use skf_mock::skf_impl::container::{skf_export_certificate, skf_export_public_key};
        let mut cert_len: u32 = 0;
        let rc = skf_export_certificate(h_container, sign_flag, std::ptr::null_mut(), &mut cert_len);
        if rc == SAR_OK && cert_len > 0 {
            let mut cert_buf = vec![0u8; cert_len as usize];
            let rc2 = skf_export_certificate(h_container, sign_flag, cert_buf.as_mut_ptr(), &mut cert_len);
            if rc2 == SAR_OK {
                return serde_json::json!({"cert_der_hex": hex::encode(&cert_buf)}).to_string();
            }
        }

        // 无证书时导出公钥
        let blob_size = std::mem::size_of::<ECCPUBLICKEYBLOB>() as u32;
        let mut blob_buf = vec![0u8; blob_size as usize];
        let mut out_len = blob_size;
        let rc = skf_export_public_key(h_container, sign_flag, blob_buf.as_mut_ptr(), &mut out_len);
        if rc != SAR_OK {
            return err_json(&format!(
                "SKF_ExportPublicKey 失败（错误码: {rc:#010x}），容器可能尚未生成密钥对"
            ));
        }
        // 安全地将字节缓冲区转换为 ECCPUBLICKEYBLOB
        // Reason: blob_buf 已按 ECCPUBLICKEYBLOB 大小分配，内存对齐安全
        let blob = unsafe { &*(blob_buf.as_ptr() as *const ECCPUBLICKEYBLOB) };
        let pub_key = sm2_ops::blob_to_pub_key(blob);
        serde_json::json!({"public_key_hex": hex::encode(&pub_key)}).to_string()
    }

    /// 工具 7：SM2 签名（使用容器内签名私钥）
    #[tool(
        description = "SM2 签名（SKF_ECCSignData），使用容器内的签名私钥。\
                       pre_hashed=false（默认）时自动对数据做 SM3(Z||data) 预处理再签名；\
                       pre_hashed=true 时直接对 32 字节摘要签名。\
                       返回 JSON：{\"signature_hex\":\"...\"} （r||s 64字节=128 hex）"
    )]
    async fn skf_sm2_sign(&self, Parameters(p): Parameters<Sm2SignParams>) -> String {
        let data = match hex::decode(&p.data_hex) {
            Ok(d) => d,
            Err(e) => return err_json(&format!("data_hex 解码失败: {e}")),
        };
        let h_container = p.container_handle as usize as *mut std::os::raw::c_void;

        // SKF_ECCSignData 内部已包含 SM3(Z||data) 处理（libsmx::sm2::sign_message）
        // 若 pre_hashed=true 则用户自行摘要好了，我们直接传入（SKF API 本来就接受原文）
        // Reason: SKF_ECCSignData 的 data 参数为"原文"，内部自动计算 Z 值和摘要
        // 若已预摘要，则包装为"原文"传入会导致二次摘要——此时使用 ext_sign 路径
        let pre_hashed = p.pre_hashed.unwrap_or(false);
        let sig_data = if pre_hashed {
            // 使用外部私钥路径：先从容器读取私钥，再调用 sm2_sign
            // Reason: 没有直接"跳过 Z 值计算"的 SKF API，pre_hashed 场景下从容器取出私钥直接调底层签名
            let result = with_device(|res| match res {
                Err(e) => Err(format!("设备未连接（错误码: {e:#010x}）")),
                Ok(ctx) => {
                    let container = ctx
                        .get_container(p.container_handle)
                        .ok_or_else(|| "容器句柄无效".to_string())?;
                    let (priv_key, _) = container
                        .sign_keypair
                        .as_ref()
                        .ok_or_else(|| "容器中没有签名密钥对".to_string())?;
                    Ok(*priv_key)
                }
            });
            match result {
                Err(e) => return err_json(&e),
                Ok(priv_key) => match sm2_ops::sm2_sign(&priv_key, &data) {
                    Some(sig) => sig.to_vec(),
                    None => return err_json("SM2 签名运算失败"),
                },
            }
        } else {
            let mut sig_blob = ECCSIGNATUREBLOB::default();
            let rc = skf_ecc_sign_data(h_container, data.as_ptr(), data.len() as u32, &mut sig_blob);
            if rc != SAR_OK {
                return err_json(&format!("SKF_ECCSignData 失败（错误码: {rc:#010x}）"));
            }
            sm2_ops::blob_to_sig(&sig_blob).to_vec()
        };

        serde_json::json!({
            "signature_hex": hex::encode(&sig_data)
        })
        .to_string()
    }

    /// 工具 8：SM2 验签（使用外部公钥）
    #[tool(
        description = "SM2 验签（SKF_ECCVerify），使用外部提供的公钥验证签名。\
                       返回 JSON：{\"valid\":true} 或 {\"error\":\"...\"}"
    )]
    async fn skf_sm2_verify(&self, Parameters(p): Parameters<Sm2VerifyParams>) -> String {
        let pub_key_bytes = match hex::decode(&p.public_key_hex) {
            Ok(d) => d,
            Err(e) => return err_json(&format!("public_key_hex 解码失败: {e}")),
        };
        if pub_key_bytes.len() != 65 || pub_key_bytes[0] != 0x04 {
            return err_json("public_key_hex 必须为 04||x||y（65字节=130 hex）格式");
        }
        let mut pk_arr = [0u8; 65];
        pk_arr.copy_from_slice(&pub_key_bytes);

        let data = match hex::decode(&p.data_hex) {
            Ok(d) => d,
            Err(e) => return err_json(&format!("data_hex 解码失败: {e}")),
        };
        let sig_bytes = match hex::decode(&p.signature_hex) {
            Ok(d) => d,
            Err(e) => return err_json(&format!("signature_hex 解码失败: {e}")),
        };
        if sig_bytes.len() != 64 {
            return err_json("signature_hex 必须为 r||s（64字节=128 hex）");
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);

        let pub_blob = sm2_ops::pub_key_to_blob(&pk_arr);

        // SKF_ECCVerify 接受设备句柄（可传 null）+ 公钥 blob + 数据 + 签名
        let sig_blob = sm2_ops::sig_to_blob(&sig_arr);
        let rc = skf_ecc_verify(
            std::ptr::null_mut(),
            &pub_blob,
            data.as_ptr(),
            data.len() as u32,
            &sig_blob,
        );

        if rc == SAR_OK {
            serde_json::json!({"valid": true}).to_string()
        } else {
            err_json(&format!("验签失败（错误码: {rc:#010x}）"))
        }
    }

    /// 工具 9：扩展 SM2 签名（外部提供私钥）
    #[tool(
        description = "扩展 SM2 签名（SKF_ExtECCSign），外部提供私钥 hex，无需容器。\
                       签名时自动计算 SM3(Z||data) 预处理。\
                       返回 JSON：{\"signature_hex\":\"...\"} （r||s 64字节）"
    )]
    async fn skf_sm2_ext_sign(&self, Parameters(p): Parameters<Sm2ExtSignParams>) -> String {
        let priv_bytes = match hex::decode(&p.private_key_hex) {
            Ok(d) => d,
            Err(e) => return err_json(&format!("private_key_hex 解码失败: {e}")),
        };
        if priv_bytes.len() != 32 {
            return err_json("private_key_hex 必须为 32 字节（64 hex）");
        }
        let mut priv_arr = [0u8; 32];
        priv_arr.copy_from_slice(&priv_bytes);
        let pri_blob = sm2_ops::pri_key_to_blob(&priv_arr);

        let data = match hex::decode(&p.data_hex) {
            Ok(d) => d,
            Err(e) => return err_json(&format!("data_hex 解码失败: {e}")),
        };

        let mut sig_blob = ECCSIGNATUREBLOB::default();
        let rc = skf_ext_ecc_sign(
            std::ptr::null_mut(),
            &pri_blob,
            data.as_ptr(),
            data.len() as u32,
            &mut sig_blob,
        );
        if rc != SAR_OK {
            return err_json(&format!("SKF_ExtECCSign 失败（错误码: {rc:#010x}）"));
        }
        let sig_64 = sm2_ops::blob_to_sig(&sig_blob);
        serde_json::json!({"signature_hex": hex::encode(&sig_64)}).to_string()
    }

    /// 工具 10：扩展 SM2 验签（外部提供公钥）
    #[tool(
        description = "扩展 SM2 验签（SKF_ExtECCVerify），外部提供公钥 hex，无需容器。\
                       返回 JSON：{\"valid\":true} 或 {\"error\":\"...\"}"
    )]
    async fn skf_sm2_ext_verify(&self, Parameters(p): Parameters<Sm2ExtVerifyParams>) -> String {
        let pub_bytes = match hex::decode(&p.public_key_hex) {
            Ok(d) => d,
            Err(e) => return err_json(&format!("public_key_hex 解码失败: {e}")),
        };
        if pub_bytes.len() != 65 || pub_bytes[0] != 0x04 {
            return err_json("public_key_hex 必须为 04||x||y（65字节=130 hex）");
        }
        let mut pk_arr = [0u8; 65];
        pk_arr.copy_from_slice(&pub_bytes);
        let pub_blob = sm2_ops::pub_key_to_blob(&pk_arr);

        let data = match hex::decode(&p.data_hex) {
            Ok(d) => d,
            Err(e) => return err_json(&format!("data_hex 解码失败: {e}")),
        };
        let sig_bytes = match hex::decode(&p.signature_hex) {
            Ok(d) => d,
            Err(e) => return err_json(&format!("signature_hex 解码失败: {e}")),
        };
        if sig_bytes.len() != 64 {
            return err_json("signature_hex 必须为 r||s（64字节=128 hex）");
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig_blob = sm2_ops::sig_to_blob(&sig_arr);

        let rc = skf_ext_ecc_verify(
            std::ptr::null_mut(),
            &pub_blob,
            data.as_ptr(),
            data.len() as u32,
            &sig_blob,
        );

        if rc == SAR_OK {
            serde_json::json!({"valid": true}).to_string()
        } else {
            err_json(&format!("扩展验签失败（错误码: {rc:#010x}）"))
        }
    }

    /// 工具 11：SM4 对称加解密
    #[tool(
        description = "SM4 对称加解密（SKF_SetSymmKey + SKF_EncryptInit + SKF_Encrypt/Decrypt）。\
                       action=\"encrypt\" 加密，action=\"decrypt\" 解密。\
                       mode=\"cbc\"（默认）或 \"ecb\"。\
                       key_hex 为 16字节=32 hex，iv_hex 为 16字节=32 hex（ECB 模式忽略 IV）。\
                       返回 JSON：{\"result_hex\":\"...\"}"
    )]
    async fn skf_sm4_crypt(&self, Parameters(p): Parameters<Sm4CryptParams>) -> String {
        let key_bytes = match hex::decode(&p.key_hex) {
            Ok(d) => d,
            Err(e) => return err_json(&format!("key_hex 解码失败: {e}")),
        };
        if key_bytes.len() != 16 {
            return err_json("key_hex 必须为 16 字节（32 hex）");
        }
        let mut key_arr = [0u8; 16];
        key_arr.copy_from_slice(&key_bytes);

        let iv_bytes = match hex::decode(&p.iv_hex) {
            Ok(d) => d,
            Err(e) => return err_json(&format!("iv_hex 解码失败: {e}")),
        };
        if iv_bytes.len() != 16 {
            return err_json("iv_hex 必须为 16 字节（32 hex）");
        }
        let mut iv_arr = [0u8; 16];
        iv_arr.copy_from_slice(&iv_bytes);

        let data = match hex::decode(&p.data_hex) {
            Ok(d) => d,
            Err(e) => return err_json(&format!("data_hex 解码失败: {e}")),
        };

        let use_cbc = p.mode.as_deref().unwrap_or("cbc") != "ecb";
        let alg_id = if use_cbc { SGD_SM4_CBC } else { SGD_SM4_ECB };

        // 设置对称密钥，获取密钥句柄
        let mut key_handle_raw: *mut std::os::raw::c_void = std::ptr::null_mut();
        let rc = skf_set_symm_key(std::ptr::null_mut(), key_arr.as_ptr(), alg_id, &mut key_handle_raw);
        if rc != SAR_OK {
            return err_json(&format!("SKF_SetSymmKey 失败（错误码: {rc:#010x}）"));
        }

        // 设置加解密参数（IV）
        let mut bcp = BLOCKCIPHERPARAM::default();
        bcp.IV[..16].copy_from_slice(&iv_arr);
        bcp.IVLen = 16;
        bcp.PaddingType = 1; // PKCS7 padding

        let is_encrypt = p.action == "encrypt";
        let rc_init = if is_encrypt {
            skf_encrypt_init(key_handle_raw, bcp)
        } else {
            skf_decrypt_init(key_handle_raw, bcp)
        };
        if rc_init != SAR_OK {
            return err_json(&format!("Init 失败（错误码: {rc_init:#010x}）"));
        }

        // 执行加解密
        let mut out_len: u32 = (data.len() + 32) as u32; // 预留 padding 空间
        let mut out_buf = vec![0u8; out_len as usize];
        let rc_op = if is_encrypt {
            skf_encrypt(
                key_handle_raw,
                data.as_ptr(),
                data.len() as u32,
                out_buf.as_mut_ptr(),
                &mut out_len,
            )
        } else {
            skf_decrypt(
                key_handle_raw,
                data.as_ptr(),
                data.len() as u32,
                out_buf.as_mut_ptr(),
                &mut out_len,
            )
        };

        if rc_op != SAR_OK {
            return err_json(&format!("加解密操作失败（错误码: {rc_op:#010x}）"));
        }
        out_buf.truncate(out_len as usize);
        serde_json::json!({"result_hex": hex::encode(&out_buf)}).to_string()
    }

    /// 工具 12：SM3 消息摘要
    #[tool(
        description = "SM3 消息摘要（SKF_DigestInit/Update/Final 完整流程）。\
                       提供 public_key_hex 时先计算 SM3(Z||data)（SM2 签名前置步骤）；\
                       不提供时为普通 SM3 摘要。\
                       返回 JSON：{\"hex\":\"...\",\"length\":32}"
    )]
    async fn skf_sm3_digest(&self, Parameters(p): Parameters<Sm3DigestParams>) -> String {
        let data = match hex::decode(&p.data_hex) {
            Ok(d) => d,
            Err(e) => return err_json(&format!("data_hex 解码失败: {e}")),
        };

        // 若提供公钥，使用带 Z 值的 SM3 摘要
        if let Some(pk_hex) = &p.public_key_hex {
            let pk_bytes = match hex::decode(pk_hex) {
                Ok(d) => d,
                Err(e) => return err_json(&format!("public_key_hex 解码失败: {e}")),
            };
            if pk_bytes.len() != 65 || pk_bytes[0] != 0x04 {
                return err_json("public_key_hex 必须为 04||x||y（65字节=130 hex）");
            }
            let mut pk_arr = [0u8; 65];
            pk_arr.copy_from_slice(&pk_bytes);

            // 使用 SKF DigestInit（传入公钥） + DigestUpdate + DigestFinal
            // Reason: skf_digest_init 接受 FFI 指针参数，此处直接调用底层 crypto 函数更简洁
            let z = sm3_ops::sm2_z_value(&pk_arr, sm2_ops::DEFAULT_USER_ID);
            let mut all_data = z.to_vec();
            all_data.extend_from_slice(&data);
            let digest = sm3_ops::sm3_digest(&all_data);

            return serde_json::json!({
                "hex": hex::encode(&digest),
                "length": digest.len()
            })
            .to_string();
        }

        // 普通 SM3
        // Reason: 无公钥时直接调用底层 sm3_digest，避免 FFI 句柄管理的复杂性
        let digest = sm3_ops::sm3_digest(&data);
        serde_json::json!({
            "hex": hex::encode(&digest),
            "length": digest.len()
        })
        .to_string()
    }
}

// ── ServerHandler 实现 ─────────────────────────────────────────────────────────

#[tool_handler]
impl ServerHandler for SkfMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(
                "SKF Mock MCP Server — 模拟 GM/T 0016-2012 智能密码钥匙接口，提供国密 SM2/SM3/SM4 能力。\
                 \n\n使用建议：\
                 \n1. 先调用 skf_device_info 获取设备状态和默认句柄\
                 \n2. 签名操作使用 skf_sm2_sign（需要 container_handle）或 skf_sm2_ext_sign（外部私钥）\
                 \n3. 验签操作使用 skf_sm2_verify 或 skf_sm2_ext_verify\
                 \n4. SM4 加解密使用 skf_sm4_crypt，支持 CBC/ECB 模式\
                 \n5. SM3 摘要使用 skf_sm3_digest，提供公钥时自动计算 Z 值前缀\
                 \n\n所有输入输出均使用 hex 编码，错误时返回 {\"error\":\"描述（错误码: 0xXXXXXXXX）\"}。\
                 \n\n仅供学习和开发测试使用，严禁用于生产环境。",
            )
    }
}

// ── 辅助函数 ─────────────────────────────────────���───────────────────────────

fn err_json(msg: &str) -> String {
    serde_json::json!({"error": msg}).to_string()
}

// ── 设备初始化 ───────────────────────────────────────────────────────────────

/// 初始化 SKF 模拟设备：连接设备并预打开默认应用和容器
/// 返回 (app_handle, container_handle)
/// Reason: 避免 LLM 每次调用时都要管理句柄生命周期，启动时统一完成初始化
fn init_skf_device() -> (u32, u32) {
    use skf_mock::skf_impl::device::skf_connect_dev;

    // 连接设备
    let dev_name = std::ffi::CString::new("MockSKFDevice").unwrap();
    let mut dev_handle: *mut std::os::raw::c_void = std::ptr::null_mut();
    let rc = skf_connect_dev(dev_name.as_ptr(), &mut dev_handle);
    if rc != SAR_OK {
        tracing::warn!("SKF_ConnectDev 失败（错误码: {rc:#010x}），设备可能未就绪");
        return (0, 0);
    }
    info!("SKF 设备已连接，设备句柄: {:?}", dev_handle);

    // 从全局上下文获取第一个应用名
    let first_app = with_device(|res| match res {
        Err(_) => None,
        Ok(ctx) => ctx.applications.keys().next().cloned(),
    });

    let app_name = match first_app {
        Some(n) => n,
        None => {
            tracing::warn!("设备中没有预配置应用，app_handle=0");
            return (0, 0);
        }
    };

    // 打开应用
    let app_name_c = std::ffi::CString::new(app_name.clone()).unwrap();
    let mut app_handle_raw: *mut std::os::raw::c_void = std::ptr::null_mut();
    let rc = skf_open_application(dev_handle, app_name_c.as_ptr(), &mut app_handle_raw);
    if rc != SAR_OK {
        tracing::warn!("SKF_OpenApplication(\"{app_name}\") 失败（错误码: {rc:#010x}）");
        return (0, 0);
    }
    let app_handle = app_handle_raw as usize as u32;
    info!("应用 \"{app_name}\" 已打开，app_handle={app_handle}");

    // 验证用户 PIN（从配置中取第一个应用的 PIN）
    let user_pin = with_device(|res| match res {
        Err(_) => "12345678".to_string(),
        Ok(ctx) => ctx
            .applications
            .get(&app_name)
            .map(|a| a.user_pin.value.clone())
            .unwrap_or_else(|| "12345678".to_string()),
    });
    let pin_c = std::ffi::CString::new(user_pin).unwrap();
    let mut remaining: u32 = 0;
    let rc = skf_verify_pin(app_handle_raw, USER_TYPE, pin_c.as_ptr(), &mut remaining);
    if rc != SAR_OK {
        tracing::warn!("SKF_VerifyPIN 失败（错误码: {rc:#010x}），remaining={remaining}");
    } else {
        info!("用户 PIN 验证成功");
    }

    // 从配置获取第一个容器名
    let first_container = with_device(|res| match res {
        Err(_) => None,
        Ok(ctx) => ctx
            .applications
            .get(&app_name)
            .and_then(|a| a.containers.keys().next().cloned()),
    });

    let container_name = first_container.unwrap_or_else(|| "DEFAULT".to_string());
    let con_name_c = std::ffi::CString::new(container_name.clone()).unwrap();
    let mut con_handle_raw: *mut std::os::raw::c_void = std::ptr::null_mut();

    // 先尝试打开已有容器
    let rc = skf_open_container(app_handle_raw, con_name_c.as_ptr(), &mut con_handle_raw);
    let container_handle = if rc == SAR_OK {
        let h = con_handle_raw as usize as u32;
        info!("容器 \"{container_name}\" 已打开，container_handle={h}");
        h
    } else {
        // 创建新容器
        let rc2 = skf_create_container(app_handle_raw, con_name_c.as_ptr(), &mut con_handle_raw);
        if rc2 == SAR_OK {
            let h = con_handle_raw as usize as u32;
            info!("容器 \"{container_name}\" 已创建，container_handle={h}");
            h
        } else {
            tracing::warn!("无法打开或创建容器 \"{container_name}\"（错误码: {rc2:#010x}），container_handle=0");
            0
        }
    };

    (app_handle, container_handle)
}

// ── main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()),
        )
        .init();

    info!("{} v{} starting", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

    // 初始化 SKF 模拟设备
    let (app_handle, container_handle) = init_skf_device();
    info!(
        "预初始化完成：app_handle={app_handle}, container_handle={container_handle}"
    );

    // 构建 MCP 服务
    let mcp_server = SkfMcpServer::new(app_handle, container_handle);
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
        session::local::LocalSessionManager,
    };
    // Reason: stateless 模式适合本地 mock 场景，无需维护 session 状态
    let config = StreamableHttpServerConfig::default().with_stateful_mode(false);
    let mcp_svc: StreamableHttpService<SkfMcpServer, LocalSessionManager> = StreamableHttpService::new(
        move || Ok(mcp_server.clone()),
        Default::default(),
        config,
    );

    let router = axum::Router::new().nest_service("/mcp", mcp_svc);
    let addr = format!("0.0.0.0:{}", cli.port);
    info!("SKF MCP Server 已启动，监听 {addr}，工具端点：POST http://{addr}/mcp");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}
