// 内存上下文管理：设备、应用、容器三级层次

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use crate::config::MockConfig;
use crate::config::mock_config::{ApplicationConfig, ContainerConfig};

// ──────── 句柄计数器 ────────
// Reason: 各类句柄从不同基址开始，便于调试时区分句柄类型
static APP_HANDLE_COUNTER: AtomicU32 = AtomicU32::new(0x00001001);
static CONTAINER_HANDLE_COUNTER: AtomicU32 = AtomicU32::new(0x00002001);
static KEY_HANDLE_COUNTER: AtomicU32 = AtomicU32::new(0x00003001);
static HASH_HANDLE_COUNTER: AtomicU32 = AtomicU32::new(0x00004001);

/// PIN 信息
#[derive(Debug, Clone)]
pub struct PinInfo {
    pub value: String,      // 当前 PIN 值
    pub max_retry: u32,     // 最大重试次数
    pub remain_retry: u32,  // 剩余重试次数
    pub locked: bool,       // 是否已锁定
}

impl PinInfo {
    pub fn new(value: String, max_retry: u32) -> Self {
        Self { remain_retry: max_retry, value, max_retry, locked: false }
    }

    /// 验证 PIN，成功返回 true，失败递减重试次数
    pub fn verify(&mut self, input: &str) -> bool {
        if self.locked {
            return false;
        }
        if self.value == input {
            self.remain_retry = self.max_retry; // 重置重试计数
            true
        } else {
            self.remain_retry = self.remain_retry.saturating_sub(1);
            if self.remain_retry == 0 {
                self.locked = true;
            }
            false
        }
    }
}

/// 文件条目
#[derive(Debug, Clone)]
pub struct FileEntry {
    pub data: Vec<u8>,
    pub size: u32,           // 分配的文件大小
    pub read_rights: u32,
    pub write_rights: u32,
}

/// 容器（存储签名/加密密钥对和证书）
#[derive(Debug, Clone, Default)]
pub struct Container {
    /// 签名密钥对：(私钥 32字节, 公钥 65字节 04||x||y)
    pub sign_keypair: Option<([u8; 32], [u8; 65])>,
    /// 加密密钥对
    pub enc_keypair: Option<([u8; 32], [u8; 65])>,
    /// 签名证书 DER
    pub sign_cert: Option<Vec<u8>>,
    /// 加密证书 DER
    pub enc_cert: Option<Vec<u8>>,
}

impl Container {
    /// 从配置构建容器（解析 hex 密钥对）
    pub fn from_config(cfg: &ContainerConfig) -> Self {
        let mut c = Container::default();

        // 解析签名密钥对
        if !cfg.sign_private_key.is_empty() && !cfg.sign_public_key_x.is_empty() {
            if let (Ok(priv_bytes), Ok(x_bytes), Ok(y_bytes)) = (
                hex::decode(&cfg.sign_private_key),
                hex::decode(&cfg.sign_public_key_x),
                hex::decode(&cfg.sign_public_key_y),
            ) {
                if priv_bytes.len() == 32 && x_bytes.len() == 32 && y_bytes.len() == 32 {
                    let mut priv_arr = [0u8; 32];
                    let mut pub_arr = [0u8; 65];
                    priv_arr.copy_from_slice(&priv_bytes);
                    pub_arr[0] = 0x04;
                    pub_arr[1..33].copy_from_slice(&x_bytes);
                    pub_arr[33..65].copy_from_slice(&y_bytes);
                    c.sign_keypair = Some((priv_arr, pub_arr));
                }
            }
        }

        // 解析加密密钥对
        if !cfg.enc_private_key.is_empty() && !cfg.enc_public_key_x.is_empty() {
            if let (Ok(priv_bytes), Ok(x_bytes), Ok(y_bytes)) = (
                hex::decode(&cfg.enc_private_key),
                hex::decode(&cfg.enc_public_key_x),
                hex::decode(&cfg.enc_public_key_y),
            ) {
                if priv_bytes.len() == 32 && x_bytes.len() == 32 && y_bytes.len() == 32 {
                    let mut priv_arr = [0u8; 32];
                    let mut pub_arr = [0u8; 65];
                    priv_arr.copy_from_slice(&priv_bytes);
                    pub_arr[0] = 0x04;
                    pub_arr[1..33].copy_from_slice(&x_bytes);
                    pub_arr[33..65].copy_from_slice(&y_bytes);
                    c.enc_keypair = Some((priv_arr, pub_arr));
                }
            }
        }

        // 解析证书
        if !cfg.sign_cert.is_empty() {
            if let Ok(der) = base64_decode_cert(&cfg.sign_cert) {
                c.sign_cert = Some(der);
            }
        }
        if !cfg.enc_cert.is_empty() {
            if let Ok(der) = base64_decode_cert(&cfg.enc_cert) {
                c.enc_cert = Some(der);
            }
        }

        c
    }
}

fn base64_decode_cert(s: &str) -> Result<Vec<u8>, ()> {
    // 支持带换行的 base64
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    // 简单 base64 解码（不依赖外部 crate，仅用于可选证书）
    // Reason: config 模块不引入 base64 crate；证书字段为可选，解码失败忽略
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut decode_table = [0u8; 256];
    for (i, &b) in alphabet.iter().enumerate() {
        decode_table[b as usize] = i as u8;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 3 < bytes.len() {
        if bytes[i] == b'=' { break; }
        let b0 = decode_table[bytes[i] as usize] as u32;
        let b1 = decode_table[bytes[i+1] as usize] as u32;
        let b2 = if bytes[i+2] == b'=' { 0 } else { decode_table[bytes[i+2] as usize] as u32 };
        let b3 = if i+3 >= bytes.len() || bytes[i+3] == b'=' { 0 } else { decode_table[bytes[i+3] as usize] as u32 };
        out.push(((b0 << 2) | (b1 >> 4)) as u8);
        if bytes[i+2] != b'=' { out.push(((b1 << 4) | (b2 >> 2)) as u8); }
        if i+3 < bytes.len() && bytes[i+3] != b'=' { out.push(((b2 << 6) | b3) as u8); }
        i += 4;
    }
    Ok(out)
}

/// 应用（包含 PIN、文件、容器）
#[derive(Debug, Clone)]
pub struct Application {
    pub name: String,
    pub admin_pin: PinInfo,
    pub user_pin: PinInfo,
    pub files: HashMap<String, FileEntry>,
    pub containers: HashMap<String, Container>,
    /// 已完成用户 PIN 验证（本次 Open 期间）
    pub user_verified: bool,
}

impl Application {
    pub fn from_config(cfg: &ApplicationConfig) -> Self {
        let mut app = Application {
            name: cfg.name.clone(),
            admin_pin: PinInfo::new(cfg.admin_pin.clone(), cfg.admin_pin_retry),
            user_pin: PinInfo::new(cfg.user_pin.clone(), cfg.user_pin_retry),
            files: HashMap::new(),
            containers: HashMap::new(),
            user_verified: false,
        };
        for c_cfg in &cfg.containers {
            app.containers.insert(c_cfg.name.clone(), Container::from_config(c_cfg));
        }
        app
    }
}

/// 对称密钥条目（SKF_SetSymmKey 或 SKF_ECCExportSessionKey 返回的句柄对应）
#[derive(Debug, Clone)]
pub struct SymKeyEntry {
    pub key_bytes: [u8; 16],  // SM4 密钥（16字节）
    pub alg_id: u32,           // 算法 ID（SGD_SM4_CBC 等）
    /// EncryptInit/DecryptInit 后设置的加解密参数
    pub cipher_param: Option<CipherParam>,
}

/// 加解密参数（由 SKF_EncryptInit / SKF_DecryptInit 设置）
#[derive(Debug, Clone)]
pub struct CipherParam {
    pub iv: [u8; 16],
    pub padding_type: u32,  // 0=不填充, 1=PKCS7
    pub for_encrypt: bool,  // true=加密模式, false=解密模式
}

/// 哈希上下文（SKF_DigestInit 创建）
#[derive(Debug, Clone)]
pub struct HashCtx {
    pub buffer: Vec<u8>,             // 累积数据（DigestUpdate 追加）
    pub pub_key: Option<[u8; 65]>,  // 若设置，DigestFinal 时先计算 Z 值
    pub user_id: Vec<u8>,            // Z 值计算的用户 ID
}

/// 全局设备上下文（单例）
pub struct DeviceContext {
    pub mock_cfg: MockConfig,
    pub label: String,
    /// 应用名 → 应用
    pub applications: HashMap<String, Application>,
    /// 应用句柄 → 应用名（open 时分配，close 时移除）
    pub app_handles: HashMap<u32, String>,
    /// 容器句柄 → (应用名, 容器名)
    pub container_handles: HashMap<u32, (String, String)>,
    /// 对称密钥句柄 → 密钥条目（SetSymmKey/ECCExportSessionKey 分配）
    pub key_handles: HashMap<u32, SymKeyEntry>,
    /// 哈希句柄 → 哈希上下文（DigestInit 分配）
    pub hash_handles: HashMap<u32, HashCtx>,
}

impl DeviceContext {
    pub fn new(cfg: MockConfig) -> Self {
        let label = cfg.device.label.clone();
        let mut apps = HashMap::new();
        for app_cfg in &cfg.applications {
            apps.insert(app_cfg.name.clone(), Application::from_config(app_cfg));
        }
        Self {
            label,
            mock_cfg: cfg,
            applications: apps,
            app_handles: HashMap::new(),
            container_handles: HashMap::new(),
            key_handles: HashMap::new(),
            hash_handles: HashMap::new(),
        }
    }

    /// 打开应用，返回应用句柄
    pub fn open_application(&mut self, name: &str) -> Option<u32> {
        if !self.applications.contains_key(name) {
            return None;
        }
        let handle = APP_HANDLE_COUNTER.fetch_add(1, Ordering::Relaxed);
        self.app_handles.insert(handle, name.to_string());
        Some(handle)
    }

    /// 关闭应用句柄，同时释放该应用下所有容器句柄
    pub fn close_application(&mut self, handle: u32) -> bool {
        if let Some(app_name) = self.app_handles.remove(&handle) {
            // 清理该应用下的容器句柄
            self.container_handles.retain(|_, (aname, _)| aname != &app_name);
            log::debug!("关闭应用句柄 0x{:08X} ({})", handle, app_name);
            true
        } else {
            false
        }
    }

    /// 打开容器，返回容器句柄
    pub fn open_container(&mut self, app_handle: u32, container_name: &str) -> Option<u32> {
        let app_name = self.app_handles.get(&app_handle)?.clone();
        let app = self.applications.get(&app_name)?;
        if !app.containers.contains_key(container_name) {
            return None;
        }
        let handle = CONTAINER_HANDLE_COUNTER.fetch_add(1, Ordering::Relaxed);
        self.container_handles.insert(handle, (app_name, container_name.to_string()));
        Some(handle)
    }

    /// 关闭容器句柄
    pub fn close_container(&mut self, handle: u32) -> bool {
        self.container_handles.remove(&handle).is_some()
    }

    /// 分配对称密钥句柄
    pub fn alloc_key_handle(&mut self, entry: SymKeyEntry) -> u32 {
        let handle = KEY_HANDLE_COUNTER.fetch_add(1, Ordering::Relaxed);
        self.key_handles.insert(handle, entry);
        handle
    }

    /// 释放对称密钥句柄
    pub fn free_key_handle(&mut self, handle: u32) -> bool {
        self.key_handles.remove(&handle).is_some()
    }

    /// 分配哈希句柄
    pub fn alloc_hash_handle(&mut self, ctx: HashCtx) -> u32 {
        let handle = HASH_HANDLE_COUNTER.fetch_add(1, Ordering::Relaxed);
        self.hash_handles.insert(handle, ctx);
        handle
    }

    /// 获取应用（通过应用句柄）
    pub fn get_app(&self, app_handle: u32) -> Option<&Application> {
        let name = self.app_handles.get(&app_handle)?;
        self.applications.get(name)
    }

    /// 获取应用（可变，通过应用句柄）
    pub fn get_app_mut(&mut self, app_handle: u32) -> Option<&mut Application> {
        let name = self.app_handles.get(&app_handle)?.clone();
        self.applications.get_mut(&name)
    }

    /// 获取容器（通过容器句柄）
    pub fn get_container(&self, con_handle: u32) -> Option<&Container> {
        let (app_name, con_name) = self.container_handles.get(&con_handle)?;
        self.applications.get(app_name)?.containers.get(con_name)
    }

    /// 获取容器（可变）
    pub fn get_container_mut(&mut self, con_handle: u32) -> Option<&mut Container> {
        let (app_name, con_name) = self.container_handles.get(&con_handle)?.clone();
        self.applications.get_mut(&app_name)?.containers.get_mut(&con_name)
    }
}
