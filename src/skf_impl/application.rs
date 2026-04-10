// 应用管理 + PIN 管理实现
// SKF_CreateApplication / SKF_EnumApplication / SKF_DeleteApplication
// SKF_OpenApplication / SKF_CloseApplication
// SKF_VerifyPIN / SKF_ChangePIN / SKF_GetPINInfo / SKF_UnblockPIN

use crate::error_code::*;
use crate::key_mgr::Application;
use crate::config::mock_config::ApplicationConfig;
use super::device::{with_device, cstr_to_string};

/// SKF_CreateApplication：创建应用
pub fn skf_create_application(
    _h_dev: *mut std::os::raw::c_void,
    sz_app_name: *const i8,
    sz_admin_pin: *const i8,
    dw_admin_retry: u32,
    sz_user_pin: *const i8,
    dw_user_retry: u32,
    _dw_create_file_rights: u32,
    ph_application: *mut *mut std::os::raw::c_void,
) -> u32 {
    if sz_app_name.is_null() || sz_admin_pin.is_null() || sz_user_pin.is_null() || ph_application.is_null() {
        return SAR_INVALIDPARAMERR;
    }
    let name = unsafe { cstr_to_string(sz_app_name) };
    let admin_pin = unsafe { cstr_to_string(sz_admin_pin) };
    let user_pin = unsafe { cstr_to_string(sz_user_pin) };

    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                if ctx.applications.contains_key(&name) {
                    return SAR_APPLICATION_EXISTS;
                }
                let cfg = ApplicationConfig {
                    name: name.clone(),
                    admin_pin,
                    user_pin,
                    admin_pin_retry: dw_admin_retry.max(1),
                    user_pin_retry: dw_user_retry.max(1),
                    containers: vec![],
                };
                ctx.applications.insert(name.clone(), Application::from_config(&cfg));

                // 同时打开此应用，返回应用句柄
                if let Some(handle) = ctx.open_application(&name) {
                    unsafe { *ph_application = handle as usize as *mut _; }
                    log::debug!("SKF_CreateApplication: 已创建并打开应用 {}", name);
                    SAR_OK
                } else {
                    SAR_FAIL
                }
            }
        }
    })
}

/// SKF_EnumApplication：枚举应用名列表（'\0' 分隔，末尾 "\0\0"）
pub fn skf_enum_application(
    _h_dev: *mut std::os::raw::c_void,
    sz_app_name: *mut i8,
    pul_size: *mut u32,
) -> u32 {
    if pul_size.is_null() {
        return SAR_INVALIDPARAMERR;
    }
    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let names: Vec<String> = ctx.applications.keys().cloned().collect();
                let needed = names.iter().map(|n| n.len() + 1).sum::<usize>() + 1;
                let buf_size = unsafe { *pul_size as usize };

                if sz_app_name.is_null() || buf_size < needed {
                    unsafe { *pul_size = needed as u32; }
                    return if sz_app_name.is_null() { SAR_OK } else { SAR_INDATALENERR };
                }

                let mut offset = 0usize;
                unsafe {
                    let buf = std::slice::from_raw_parts_mut(sz_app_name as *mut u8, needed);
                    for name in &names {
                        let bytes = name.as_bytes();
                        buf[offset..offset + bytes.len()].copy_from_slice(bytes);
                        offset += bytes.len();
                        buf[offset] = 0;
                        offset += 1;
                    }
                    buf[offset] = 0; // 末尾额外 \0
                    *pul_size = needed as u32;
                }
                SAR_OK
            }
        }
    })
}

/// SKF_DeleteApplication：删除应用
pub fn skf_delete_application(_h_dev: *mut std::os::raw::c_void, sz_app_name: *const i8) -> u32 {
    if sz_app_name.is_null() {
        return SAR_INVALIDPARAMERR;
    }
    let name = unsafe { cstr_to_string(sz_app_name) };
    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                if ctx.applications.remove(&name).is_none() {
                    return SAR_APPLICATION_NOT_EXISTS;
                }
                // 清理该应用的所有句柄
                ctx.app_handles.retain(|_, v| v != &name);
                ctx.container_handles.retain(|_, (a, _)| a != &name);
                log::debug!("SKF_DeleteApplication: 已删除应用 {}", name);
                SAR_OK
            }
        }
    })
}

/// SKF_OpenApplication：打开应用，返回应用句柄
pub fn skf_open_application(
    _h_dev: *mut std::os::raw::c_void,
    sz_app_name: *const i8,
    ph_application: *mut *mut std::os::raw::c_void,
) -> u32 {
    if sz_app_name.is_null() || ph_application.is_null() {
        return SAR_INVALIDPARAMERR;
    }
    let name = unsafe { cstr_to_string(sz_app_name) };
    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                match ctx.open_application(&name) {
                    Some(handle) => {
                        unsafe { *ph_application = handle as usize as *mut _; }
                        log::debug!("SKF_OpenApplication: {} → handle=0x{:08X}", name, handle);
                        SAR_OK
                    }
                    None => SAR_APPLICATION_NOT_EXISTS,
                }
            }
        }
    })
}

/// SKF_CloseApplication：关闭应用句柄
pub fn skf_close_application(h_application: *mut std::os::raw::c_void) -> u32 {
    let handle = h_application as usize as u32;
    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                if ctx.close_application(handle) {
                    log::debug!("SKF_CloseApplication: handle=0x{:08X}", handle);
                    SAR_OK
                } else {
                    SAR_INVALIDHANDLEERR
                }
            }
        }
    })
}

// ──────── PIN 管理 ────────

/// SKF_VerifyPIN：验证 PIN（ADMIN_TYPE=0 或 USER_TYPE=1）
pub fn skf_verify_pin(
    h_application: *mut std::os::raw::c_void,
    ul_pin_type: u32,
    sz_pin: *const i8,
    pul_retry_count: *mut u32,
) -> u32 {
    if sz_pin.is_null() {
        return SAR_INVALIDPARAMERR;
    }
    if ul_pin_type != ADMIN_TYPE && ul_pin_type != USER_TYPE {
        return SAR_USER_TYPE_INVALID;
    }
    let pin = unsafe { cstr_to_string(sz_pin) };
    let handle = h_application as usize as u32;

    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let app = match ctx.get_app_mut(handle) {
                    Some(a) => a,
                    None => return SAR_INVALIDHANDLEERR,
                };
                let pin_info = if ul_pin_type == ADMIN_TYPE {
                    &mut app.admin_pin
                } else {
                    &mut app.user_pin
                };

                if pin_info.locked {
                    if !pul_retry_count.is_null() {
                        unsafe { *pul_retry_count = 0; }
                    }
                    return SAR_PIN_LOCKED;
                }

                if pin_info.verify(&pin) {
                    if ul_pin_type == USER_TYPE {
                        app.user_verified = true;
                    }
                    log::debug!("SKF_VerifyPIN: PIN 验证成功（type={}）", ul_pin_type);
                    SAR_OK
                } else {
                    let remain = pin_info.remain_retry;
                    if !pul_retry_count.is_null() {
                        unsafe { *pul_retry_count = remain; }
                    }
                    log::warn!("SKF_VerifyPIN: PIN 错误，剩余重试 {}", remain);
                    if pin_info.locked { SAR_PIN_LOCKED } else { SAR_PIN_INCORRECT }
                }
            }
        }
    })
}

/// SKF_ChangePIN：修改 PIN
pub fn skf_change_pin(
    h_application: *mut std::os::raw::c_void,
    ul_pin_type: u32,
    sz_old_pin: *const i8,
    sz_new_pin: *const i8,
    pul_retry_count: *mut u32,
) -> u32 {
    if sz_old_pin.is_null() || sz_new_pin.is_null() {
        return SAR_INVALIDPARAMERR;
    }
    let old_pin = unsafe { cstr_to_string(sz_old_pin) };
    let new_pin = unsafe { cstr_to_string(sz_new_pin) };
    let handle = h_application as usize as u32;

    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let app = match ctx.get_app_mut(handle) {
                    Some(a) => a,
                    None => return SAR_INVALIDHANDLEERR,
                };
                let pin_info = if ul_pin_type == ADMIN_TYPE {
                    &mut app.admin_pin
                } else {
                    &mut app.user_pin
                };

                if pin_info.locked {
                    return SAR_PIN_LOCKED;
                }
                if !pin_info.verify(&old_pin) {
                    let remain = pin_info.remain_retry;
                    if !pul_retry_count.is_null() {
                        unsafe { *pul_retry_count = remain; }
                    }
                    return SAR_PIN_INCORRECT;
                }
                pin_info.value = new_pin;
                SAR_OK
            }
        }
    })
}

/// SKF_GetPINInfo：获取 PIN 信息
pub fn skf_get_pin_info(
    h_application: *mut std::os::raw::c_void,
    ul_pin_type: u32,
    pul_max_retry: *mut u32,
    pul_remain_retry: *mut u32,
    pb_default_pin: *mut i32,
) -> u32 {
    if pul_max_retry.is_null() || pul_remain_retry.is_null() || pb_default_pin.is_null() {
        return SAR_INVALIDPARAMERR;
    }
    let handle = h_application as usize as u32;
    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let app = match ctx.get_app(handle) {
                    Some(a) => a,
                    None => return SAR_INVALIDHANDLEERR,
                };
                let pin_info = if ul_pin_type == ADMIN_TYPE {
                    &app.admin_pin
                } else {
                    &app.user_pin
                };
                unsafe {
                    *pul_max_retry = pin_info.max_retry;
                    *pul_remain_retry = pin_info.remain_retry;
                    *pb_default_pin = 0; // 非默认 PIN
                }
                SAR_OK
            }
        }
    })
}

/// SKF_UnblockPIN：用管理员 PIN 解锁用户 PIN
pub fn skf_unblock_pin(
    h_application: *mut std::os::raw::c_void,
    sz_admin_pin: *const i8,
    sz_new_user_pin: *const i8,
    pul_retry_count: *mut u32,
) -> u32 {
    if sz_admin_pin.is_null() || sz_new_user_pin.is_null() {
        return SAR_INVALIDPARAMERR;
    }
    let admin_pin = unsafe { cstr_to_string(sz_admin_pin) };
    let new_user_pin = unsafe { cstr_to_string(sz_new_user_pin) };
    let handle = h_application as usize as u32;

    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let app = match ctx.get_app_mut(handle) {
                    Some(a) => a,
                    None => return SAR_INVALIDHANDLEERR,
                };
                // 先验证管理员 PIN
                if !app.admin_pin.verify(&admin_pin) {
                    let remain = app.admin_pin.remain_retry;
                    if !pul_retry_count.is_null() {
                        unsafe { *pul_retry_count = remain; }
                    }
                    return SAR_PIN_INCORRECT;
                }
                // 解锁用户 PIN 并设置新值
                app.user_pin.locked = false;
                app.user_pin.remain_retry = app.user_pin.max_retry;
                app.user_pin.value = new_user_pin;
                log::debug!("SKF_UnblockPIN: 用户 PIN 已解锁");
                SAR_OK
            }
        }
    })
}
