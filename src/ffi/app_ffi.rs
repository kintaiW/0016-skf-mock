// 应用管理 + PIN 管理 FFI 导出
use std::os::raw::{c_void, c_char, c_int};
use crate::skf_impl::application::*;

/// SKF_CreateApplication
#[no_mangle]
pub extern "C" fn SKF_CreateApplication(
    h_dev: *mut c_void,
    sz_app_name: *const c_char,
    sz_admin_pin: *const c_char,
    dw_admin_retry: u32,
    sz_user_pin: *const c_char,
    dw_user_retry: u32,
    dw_create_file_rights: u32,
    ph_application: *mut *mut c_void,
) -> u32 {
    skf_create_application(
        h_dev,
        sz_app_name as *const i8,
        sz_admin_pin as *const i8,
        dw_admin_retry,
        sz_user_pin as *const i8,
        dw_user_retry,
        dw_create_file_rights,
        ph_application,
    )
}

/// SKF_EnumApplication
#[no_mangle]
pub extern "C" fn SKF_EnumApplication(
    h_dev: *mut c_void,
    sz_app_name: *mut c_char,
    pul_size: *mut u32,
) -> u32 {
    skf_enum_application(h_dev, sz_app_name as *mut i8, pul_size)
}

/// SKF_DeleteApplication
#[no_mangle]
pub extern "C" fn SKF_DeleteApplication(h_dev: *mut c_void, sz_app_name: *const c_char) -> u32 {
    skf_delete_application(h_dev, sz_app_name as *const i8)
}

/// SKF_OpenApplication
#[no_mangle]
pub extern "C" fn SKF_OpenApplication(
    h_dev: *mut c_void,
    sz_app_name: *const c_char,
    ph_application: *mut *mut c_void,
) -> u32 {
    skf_open_application(h_dev, sz_app_name as *const i8, ph_application)
}

/// SKF_CloseApplication
#[no_mangle]
pub extern "C" fn SKF_CloseApplication(h_application: *mut c_void) -> u32 {
    skf_close_application(h_application)
}

/// SKF_VerifyPIN
#[no_mangle]
pub extern "C" fn SKF_VerifyPIN(
    h_application: *mut c_void,
    ul_pin_type: u32,
    sz_pin: *const c_char,
    pul_retry_count: *mut u32,
) -> u32 {
    skf_verify_pin(h_application, ul_pin_type, sz_pin as *const i8, pul_retry_count)
}

/// SKF_ChangePIN
#[no_mangle]
pub extern "C" fn SKF_ChangePIN(
    h_application: *mut c_void,
    ul_pin_type: u32,
    sz_old_pin: *const c_char,
    sz_new_pin: *const c_char,
    pul_retry_count: *mut u32,
) -> u32 {
    skf_change_pin(
        h_application,
        ul_pin_type,
        sz_old_pin as *const i8,
        sz_new_pin as *const i8,
        pul_retry_count,
    )
}

/// SKF_GetPINInfo
#[no_mangle]
pub extern "C" fn SKF_GetPINInfo(
    h_application: *mut c_void,
    ul_pin_type: u32,
    pul_max_retry: *mut u32,
    pul_remain_retry: *mut u32,
    pb_default_pin: *mut c_int,
) -> u32 {
    skf_get_pin_info(h_application, ul_pin_type, pul_max_retry, pul_remain_retry, pb_default_pin as *mut i32)
}

/// SKF_UnblockPIN
#[no_mangle]
pub extern "C" fn SKF_UnblockPIN(
    h_application: *mut c_void,
    sz_admin_pin: *const c_char,
    sz_new_user_pin: *const c_char,
    pul_retry_count: *mut u32,
) -> u32 {
    skf_unblock_pin(
        h_application,
        sz_admin_pin as *const i8,
        sz_new_user_pin as *const i8,
        pul_retry_count,
    )
}

/// SKF_ClearSecureState：清除安全状态（Mock：返回成功）
#[no_mangle]
pub extern "C" fn SKF_ClearSecureState(_h_application: *mut c_void) -> u32 {
    crate::error_code::SAR_OK
}
