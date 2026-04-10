// 设备管理 FFI 导出
use std::os::raw::{c_void, c_char, c_int};
use crate::types::DEVINFO;
use crate::skf_impl::device::*;

/// SKF_WaitForDevEvent：等待设备事件（Mock：立即返回设备名）
#[no_mangle]
pub extern "C" fn SKF_WaitForDevEvent(
    sz_dev_name: *mut c_char,
    pul_dev_name_len: *mut u32,
    pul_event: *mut u32,
) -> u32 {
    if pul_dev_name_len.is_null() || pul_event.is_null() {
        return crate::error_code::SAR_INVALIDPARAMERR;
    }
    // Mock：设备始终就绪，立即返回插入事件
    let dev_name = b"MockSKFDevice\0";
    unsafe {
        if !sz_dev_name.is_null() {
            std::ptr::copy_nonoverlapping(dev_name.as_ptr() as *const c_char, sz_dev_name, dev_name.len());
        }
        *pul_dev_name_len = (dev_name.len() - 1) as u32;
        *pul_event = 1; // 设备插入事件
    }
    crate::error_code::SAR_OK
}

/// SKF_CancelWaitForDevEvent：取消等待设备事件
#[no_mangle]
pub extern "C" fn SKF_CancelWaitForDevEvent() -> u32 {
    crate::error_code::SAR_OK
}

/// SKF_EnumDev：枚举设备
#[no_mangle]
pub extern "C" fn SKF_EnumDev(_b_present: c_int, sz_name_list: *mut c_char, pul_size: *mut u32) -> u32 {
    skf_enum_dev(sz_name_list as *mut i8, pul_size)
}

/// SKF_ConnectDev：连接设备
#[no_mangle]
pub extern "C" fn SKF_ConnectDev(sz_name: *const c_char, ph_dev: *mut *mut c_void) -> u32 {
    skf_connect_dev(sz_name as *const i8, ph_dev)
}

/// SKF_DisConnectDev：断开设备
#[no_mangle]
pub extern "C" fn SKF_DisConnectDev(h_dev: *mut c_void) -> u32 {
    skf_disconnect_dev(h_dev)
}

/// SKF_GetDevState：查询设备状态
#[no_mangle]
pub extern "C" fn SKF_GetDevState(sz_dev_name: *const c_char, pul_dev_state: *mut u32) -> u32 {
    skf_get_dev_state(sz_dev_name as *const i8, pul_dev_state)
}

/// SKF_SetLabel：设置设备标签
#[no_mangle]
pub extern "C" fn SKF_SetLabel(h_dev: *mut c_void, sz_label: *const c_char) -> u32 {
    skf_set_label(h_dev, sz_label as *const i8)
}

/// SKF_GetDevInfo：获取设备信息
#[no_mangle]
pub extern "C" fn SKF_GetDevInfo(h_dev: *mut c_void, p_dev_info: *mut DEVINFO) -> u32 {
    skf_get_dev_info(h_dev, p_dev_info)
}

/// SKF_LockDev：锁定设备（Mock：直接返回成功）
#[no_mangle]
pub extern "C" fn SKF_LockDev(_h_dev: *mut c_void, _ul_time_out: u32) -> u32 {
    crate::error_code::SAR_OK
}

/// SKF_UnlockDev：解锁设备（Mock：直接返回成功）
#[no_mangle]
pub extern "C" fn SKF_UnlockDev(_h_dev: *mut c_void) -> u32 {
    crate::error_code::SAR_OK
}

/// SKF_Transmit：透传命令（Mock：不支持）
#[no_mangle]
pub extern "C" fn SKF_Transmit(
    _h_dev: *mut c_void,
    _pb_command: *const u8,
    _ul_command_len: u32,
    _pb_data: *mut u8,
    _pul_data_len: *mut u32,
) -> u32 {
    crate::error_code::SAR_NOTSUPPORTYETERR
}

/// SKF_GenRandom：生成随机数
#[no_mangle]
pub extern "C" fn SKF_GenRandom(h_dev: *mut c_void, pb_random: *mut u8, ul_random_len: u32) -> u32 {
    skf_gen_random(h_dev, pb_random, ul_random_len)
}

/// SKF_DevAuth：设备认证（Mock：直接返回成功）
#[no_mangle]
pub extern "C" fn SKF_DevAuth(_h_dev: *mut c_void, _pb_auth_data: *const u8, _ul_len: u32) -> u32 {
    crate::error_code::SAR_OK
}

/// SKF_ChangeDevAuthKey：更改设备认证密钥（Mock：直接返回成功）
#[no_mangle]
pub extern "C" fn SKF_ChangeDevAuthKey(_h_dev: *mut c_void, _pb_key_value: *const u8, _ul_key_len: u32) -> u32 {
    crate::error_code::SAR_OK
}
