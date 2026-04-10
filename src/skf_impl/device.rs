// 设备管理实现
// SKF_EnumDev / SKF_ConnectDev / SKF_DisConnectDev / SKF_GetDevInfo / SKF_GenRandom

use std::sync::{Mutex, OnceLock};
use crate::config::MockConfig;
use crate::error_code::*;
use crate::key_mgr::DeviceContext;

/// 全局设备上下文（单例）
/// Reason: SKF 标准中 USB Key 是全局唯一设备，OnceLock+Mutex 保证初始化一次且线程安全
static DEVICE_CTX: OnceLock<Mutex<Option<DeviceContext>>> = OnceLock::new();

pub(crate) fn device_lock() -> &'static Mutex<Option<DeviceContext>> {
    DEVICE_CTX.get_or_init(|| Mutex::new(None))
}

/// 辅助：在已持有设备锁的情况下执行操作
/// Reason: 统一句柄校验入口，避免各函数重复加锁+检查设备状态代码
pub fn with_device<F, R>(f: F) -> R
where
    F: FnOnce(Result<&mut DeviceContext, u32>) -> R,
{
    let mut guard = device_lock().lock().unwrap_or_else(|e| e.into_inner());
    match guard.as_mut() {
        Some(ctx) => f(Ok(ctx)),
        None => f(Err(SAR_FAIL)),  // 设备未连接
    }
}

/// SKF_EnumDev：枚举可用设备名称
/// szNameList: 输出设备名列表（名称之间以 '\0' 分隔，末尾 "\0\0"）
/// pulSize: 输入时为 szNameList 缓冲区大小，输出时为实际填充字节数
pub fn skf_enum_dev(sz_name_list: *mut i8, pul_size: *mut u32) -> u32 {
    if pul_size.is_null() {
        return SAR_INVALIDPARAMERR;
    }

    // 仅返回配置的设备名（Mock 始终有一个设备）
    // 先尝试从全局配置获取设备名，若未连接则用默认名
    let dev_name = {
        let guard = device_lock().lock().unwrap_or_else(|e| e.into_inner());
        guard.as_ref()
            .map(|ctx| ctx.mock_cfg.device.name.clone())
            .unwrap_or_else(|| "MockSKFDevice".to_string())
    };

    // 格式：name\0\0（结尾两个 \0）
    let name_bytes = dev_name.as_bytes();
    let needed = name_bytes.len() + 2; // name + '\0' + '\0'

    unsafe {
        let buf_size = *pul_size as usize;
        if sz_name_list.is_null() || buf_size < needed {
            *pul_size = needed as u32;
            return if sz_name_list.is_null() { SAR_OK } else { SAR_INDATALENERR };
        }
        let out = std::slice::from_raw_parts_mut(sz_name_list as *mut u8, needed);
        out[..name_bytes.len()].copy_from_slice(name_bytes);
        out[name_bytes.len()] = 0;
        out[name_bytes.len() + 1] = 0;
        *pul_size = needed as u32;
    }
    SAR_OK
}

/// SKF_ConnectDev：连接设备，初始化全局上下文
pub fn skf_connect_dev(sz_name: *const i8, ph_dev: *mut *mut std::os::raw::c_void) -> u32 {
    if sz_name.is_null() || ph_dev.is_null() {
        return SAR_INVALIDPARAMERR;
    }

    // 初始化日志（仅第一次生效）
    let _ = env_logger::try_init();

    let cfg = MockConfig::load();
    let mut guard = device_lock().lock().unwrap_or_else(|e| e.into_inner());

    if let Some(ctx) = guard.as_mut() {
        // 已连接：引用计数+1
        ctx.mock_cfg.applications.len(); // 仅确保结构有效
        log::warn!("SKF_ConnectDev: 设备已连接，返回成功");
        unsafe { *ph_dev = 1usize as *mut _; }
        return SAR_OK;
    }

    *guard = Some(DeviceContext::new(cfg));
    log::info!("SKF_ConnectDev: 设备已连接");
    unsafe { *ph_dev = 1usize as *mut _; }  // Mock 设备句柄固定为 1
    SAR_OK
}

/// SKF_DisConnectDev：断开设备，销毁全局上下文
pub fn skf_disconnect_dev(_h_dev: *mut std::os::raw::c_void) -> u32 {
    let mut guard = device_lock().lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        log::warn!("SKF_DisConnectDev: 设备未连接");
        return SAR_FAIL;
    }
    *guard = None;
    log::info!("SKF_DisConnectDev: 设备已断开");
    SAR_OK
}

/// SKF_GetDevState：查询设备状态（不需要已连接）
pub fn skf_get_dev_state(_sz_dev_name: *const i8, pul_dev_state: *mut u32) -> u32 {
    if pul_dev_state.is_null() {
        return SAR_INVALIDPARAMERR;
    }
    // Mock 始终返回"设备就绪"
    unsafe { *pul_dev_state = DEV_PRESENT; }
    SAR_OK
}

/// SKF_GetDevInfo：获取设备信息
pub fn skf_get_dev_info(_h_dev: *mut std::os::raw::c_void, p_dev_info: *mut crate::types::DEVINFO) -> u32 {
    if p_dev_info.is_null() {
        return SAR_INVALIDPARAMERR;
    }
    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let mut info = crate::types::DEVINFO::default();
                copy_str_to_buf(&ctx.mock_cfg.device.manufacturer, &mut info.Manufacturer);
                copy_str_to_buf(&ctx.mock_cfg.device.serial, &mut info.SerialNumber);
                copy_str_to_buf(&ctx.label, &mut info.Label);
                unsafe { *p_dev_info = info; }
                log::debug!("SKF_GetDevInfo: 返回设备信息");
                SAR_OK
            }
        }
    })
}

/// SKF_SetLabel：设置设备标签（内存修改）
pub fn skf_set_label(_h_dev: *mut std::os::raw::c_void, sz_label: *const i8) -> u32 {
    if sz_label.is_null() {
        return SAR_INVALIDPARAMERR;
    }
    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let label = unsafe { cstr_to_string(sz_label) };
                ctx.label = label;
                SAR_OK
            }
        }
    })
}

/// SKF_GenRandom：生成随机数
pub fn skf_gen_random(_h_dev: *mut std::os::raw::c_void, pb_random: *mut u8, ul_random_len: u32) -> u32 {
    if pb_random.is_null() || ul_random_len == 0 {
        return SAR_INVALIDPARAMERR;
    }
    use rand::RngCore;
    let buf = unsafe { std::slice::from_raw_parts_mut(pb_random, ul_random_len as usize) };
    rand::rngs::OsRng.fill_bytes(buf);
    SAR_OK
}

// ──────────── 辅助函数 ────────────

/// 将字符串复制到固定大小 u8 数组（截断处理）
pub fn copy_str_to_buf(s: &str, buf: &mut [u8]) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(buf.len());
    buf[..len].copy_from_slice(&bytes[..len]);
}

/// 将 C 字符串转为 Rust String（null 结尾）
pub unsafe fn cstr_to_string(ptr: *const i8) -> String {
    let cstr = std::ffi::CStr::from_ptr(ptr);
    cstr.to_string_lossy().into_owned()
}
