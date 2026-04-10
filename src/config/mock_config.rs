// mock_keys.toml 解析
// 查找优先级：环境变量 SKF_MOCK_CONFIG → 当前工作目录 mock_keys.toml

use serde::Deserialize;

/// 容器配置（签名/加密密钥对 + 证书）
#[derive(Debug, Deserialize, Clone)]
pub struct ContainerConfig {
    pub name: String,
    /// 签名私钥（32字节 hex）
    #[serde(default)]
    pub sign_private_key: String,
    /// 签名公钥 X 坐标（32字节 hex，右对齐）
    #[serde(default)]
    pub sign_public_key_x: String,
    /// 签名公钥 Y 坐标（32字节 hex，右对齐）
    #[serde(default)]
    pub sign_public_key_y: String,
    /// 加密私钥（32字节 hex）
    #[serde(default)]
    pub enc_private_key: String,
    /// 加密公钥 X 坐标（32字节 hex，右对齐）
    #[serde(default)]
    pub enc_public_key_x: String,
    /// 加密公钥 Y 坐标（32字节 hex，右对齐）
    #[serde(default)]
    pub enc_public_key_y: String,
    /// 签名证书（DER base64）
    #[serde(default)]
    pub sign_cert: String,
    /// 加密证书（DER base64）
    #[serde(default)]
    pub enc_cert: String,
}

/// 应用配置
#[derive(Debug, Deserialize, Clone)]
pub struct ApplicationConfig {
    pub name: String,
    #[serde(default = "default_pin")]
    pub admin_pin: String,
    #[serde(default = "default_pin")]
    pub user_pin: String,
    #[serde(default = "default_retry")]
    pub admin_pin_retry: u32,
    #[serde(default = "default_retry")]
    pub user_pin_retry: u32,
    #[serde(default)]
    pub containers: Vec<ContainerConfig>,
}

fn default_pin() -> String { "12345678".to_string() }
fn default_retry() -> u32 { 10 }

/// 设备配置
#[derive(Debug, Deserialize, Clone)]
pub struct DeviceConfig {
    #[serde(default = "default_dev_name")]
    pub name: String,
    #[serde(default = "default_manufacturer")]
    pub manufacturer: String,
    #[serde(default = "default_serial")]
    pub serial: String,
    #[serde(default = "default_label")]
    pub label: String,
}

fn default_dev_name() -> String { "MockSKFDevice".to_string() }
fn default_manufacturer() -> String { "Mock Manufacturer".to_string() }
fn default_serial() -> String { "MOCK-SKF-001".to_string() }
fn default_label() -> String { "Test Token".to_string() }

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            name: default_dev_name(),
            manufacturer: default_manufacturer(),
            serial: default_serial(),
            label: default_label(),
        }
    }
}

/// 完整 mock 配置
#[derive(Debug, Deserialize, Clone, Default)]
pub struct MockConfig {
    #[serde(default)]
    pub device: DeviceConfig,
    #[serde(default)]
    pub applications: Vec<ApplicationConfig>,
}

impl MockConfig {
    /// 从环境变量 SKF_MOCK_CONFIG 或当前工作目录加载 mock_keys.toml
    /// 找不到配置文件时返回默认配置（空配置），不报错
    pub fn load() -> Self {
        let path = if let Ok(p) = std::env::var("SKF_MOCK_CONFIG") {
            p
        } else {
            "mock_keys.toml".to_string()
        };

        match std::fs::read_to_string(&path) {
            Ok(content) => {
                match toml::from_str::<MockConfig>(&content) {
                    Ok(cfg) => {
                        log::info!("已加载配置: {} ({} 个应用)", path, cfg.applications.len());
                        cfg
                    }
                    Err(e) => {
                        log::warn!("配置文件解析失败 {}: {}，使用默认配置", path, e);
                        MockConfig::default()
                    }
                }
            }
            Err(_) => {
                log::info!("未找到配置文件 {}，使用默认配置（空设备）", path);
                MockConfig::default()
            }
        }
    }
}
