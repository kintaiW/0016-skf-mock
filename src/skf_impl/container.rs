// 容器管理 + 文件管理 + 证书/公钥 实现
// SKF_CreateContainer / SKF_DeleteContainer / SKF_EnumContainer
// SKF_OpenContainer / SKF_CloseContainer / SKF_GetContainerType
// SKF_CreateFile / SKF_DeleteFile / SKF_EnumFiles / SKF_GetFileInfo / SKF_ReadFile / SKF_WriteFile
// SKF_ImportCertificate / SKF_ExportCertificate / SKF_ExportPublicKey

use crate::error_code::*;
use crate::key_mgr::{Container, FileEntry};
use crate::types::{FILEATTRIBUTE, ECCPUBLICKEYBLOB};
use super::device::{with_device, cstr_to_string, copy_str_to_buf};

// ──────── 容器管理 ────────

/// SKF_CreateContainer：创建容器
pub fn skf_create_container(
    h_application: *mut std::os::raw::c_void,
    sz_container_name: *const i8,
    ph_container: *mut *mut std::os::raw::c_void,
) -> u32 {
    if sz_container_name.is_null() || ph_container.is_null() {
        return SAR_INVALIDPARAMERR;
    }
    let name = unsafe { cstr_to_string(sz_container_name) };
    let app_handle = h_application as usize as u32;

    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let app_name = match ctx.app_handles.get(&app_handle).cloned() {
                    Some(n) => n,
                    None => return SAR_INVALIDHANDLEERR,
                };
                let app = match ctx.applications.get_mut(&app_name) {
                    Some(a) => a,
                    None => return SAR_INVALIDHANDLEERR,
                };
                if app.containers.contains_key(&name) {
                    return SAR_CONTAINER_EXISTS;
                }
                app.containers.insert(name.clone(), Container::default());

                // 同时打开容器
                // Reason: CreateContainer 规范要求返回容器句柄，与 0018 的会话模式一致
                drop(app); // release borrow before calling ctx methods
                let handle = match ctx.open_container(app_handle, &name) {
                    Some(h) => h,
                    None => return SAR_FAIL,
                };
                unsafe { *ph_container = handle as usize as *mut _; }
                log::debug!("SKF_CreateContainer: 已创建容器 {}", name);
                SAR_OK
            }
        }
    })
}

/// SKF_DeleteContainer：删除容器
pub fn skf_delete_container(h_application: *mut std::os::raw::c_void, sz_container_name: *const i8) -> u32 {
    if sz_container_name.is_null() {
        return SAR_INVALIDPARAMERR;
    }
    let name = unsafe { cstr_to_string(sz_container_name) };
    let app_handle = h_application as usize as u32;

    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let app_name = match ctx.app_handles.get(&app_handle).cloned() {
                    Some(n) => n,
                    None => return SAR_INVALIDHANDLEERR,
                };
                let app = match ctx.applications.get_mut(&app_name) {
                    Some(a) => a,
                    None => return SAR_INVALIDHANDLEERR,
                };
                if app.containers.remove(&name).is_none() {
                    return SAR_CONTAINER_NOT_EXISTS;
                }
                // 清理容器句柄
                ctx.container_handles.retain(|_, (an, cn)| !(an == &app_name && cn == &name));
                SAR_OK
            }
        }
    })
}

/// SKF_EnumContainer：枚举容器名（'\0' 分隔）
pub fn skf_enum_container(
    h_application: *mut std::os::raw::c_void,
    sz_container_name: *mut i8,
    pul_size: *mut u32,
) -> u32 {
    if pul_size.is_null() {
        return SAR_INVALIDPARAMERR;
    }
    let app_handle = h_application as usize as u32;
    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let app = match ctx.get_app(app_handle) {
                    Some(a) => a,
                    None => return SAR_INVALIDHANDLEERR,
                };
                let names: Vec<String> = app.containers.keys().cloned().collect();
                let needed = names.iter().map(|n| n.len() + 1).sum::<usize>() + 1;
                let buf_size = unsafe { *pul_size as usize };

                if sz_container_name.is_null() || buf_size < needed {
                    unsafe { *pul_size = needed as u32; }
                    return if sz_container_name.is_null() { SAR_OK } else { SAR_INDATALENERR };
                }

                let mut offset = 0usize;
                unsafe {
                    let buf = std::slice::from_raw_parts_mut(sz_container_name as *mut u8, needed);
                    for name in &names {
                        let bytes = name.as_bytes();
                        buf[offset..offset + bytes.len()].copy_from_slice(bytes);
                        offset += bytes.len();
                        buf[offset] = 0;
                        offset += 1;
                    }
                    buf[offset] = 0;
                    *pul_size = needed as u32;
                }
                SAR_OK
            }
        }
    })
}

/// SKF_OpenContainer：打开容器，返回容器句柄
pub fn skf_open_container(
    h_application: *mut std::os::raw::c_void,
    sz_container_name: *const i8,
    ph_container: *mut *mut std::os::raw::c_void,
) -> u32 {
    if sz_container_name.is_null() || ph_container.is_null() {
        return SAR_INVALIDPARAMERR;
    }
    let name = unsafe { cstr_to_string(sz_container_name) };
    let app_handle = h_application as usize as u32;

    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                match ctx.open_container(app_handle, &name) {
                    Some(handle) => {
                        unsafe { *ph_container = handle as usize as *mut _; }
                        log::debug!("SKF_OpenContainer: {} → 0x{:08X}", name, handle);
                        SAR_OK
                    }
                    None => SAR_CONTAINER_NOT_EXISTS,
                }
            }
        }
    })
}

/// SKF_CloseContainer：关闭容器句柄
pub fn skf_close_container(h_container: *mut std::os::raw::c_void) -> u32 {
    let handle = h_container as usize as u32;
    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                if ctx.close_container(handle) { SAR_OK } else { SAR_INVALIDHANDLEERR }
            }
        }
    })
}

/// SKF_GetContainerType：获取容器类型（0=空, 1=RSA, 2=ECC）
pub fn skf_get_container_type(h_container: *mut std::os::raw::c_void, pul_container_type: *mut u32) -> u32 {
    if pul_container_type.is_null() {
        return SAR_INVALIDPARAMERR;
    }
    let handle = h_container as usize as u32;
    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let container = match ctx.get_container(handle) {
                    Some(c) => c,
                    None => return SAR_INVALIDHANDLEERR,
                };
                let typ = if container.sign_keypair.is_some() || container.enc_keypair.is_some() {
                    CONTAINER_TYPE_ECC
                } else {
                    CONTAINER_TYPE_EMPTY
                };
                unsafe { *pul_container_type = typ; }
                SAR_OK
            }
        }
    })
}

// ──────── 文件管理 ────────

/// SKF_CreateFile：创建文件
pub fn skf_create_file(
    h_application: *mut std::os::raw::c_void,
    sz_file_name: *const i8,
    ul_file_size: u32,
    ul_read_rights: u32,
    ul_write_rights: u32,
) -> u32 {
    if sz_file_name.is_null() {
        return SAR_INVALIDPARAMERR;
    }
    let name = unsafe { cstr_to_string(sz_file_name) };
    let app_handle = h_application as usize as u32;
    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let app = match ctx.get_app_mut(app_handle) {
                    Some(a) => a,
                    None => return SAR_INVALIDHANDLEERR,
                };
                if app.files.contains_key(&name) {
                    return SAR_FILEERR; // 文件已存在
                }
                app.files.insert(name, FileEntry {
                    data: vec![0u8; ul_file_size as usize],
                    size: ul_file_size,
                    read_rights: ul_read_rights,
                    write_rights: ul_write_rights,
                });
                SAR_OK
            }
        }
    })
}

/// SKF_DeleteFile：删除文件
pub fn skf_delete_file(h_application: *mut std::os::raw::c_void, sz_file_name: *const i8) -> u32 {
    if sz_file_name.is_null() { return SAR_INVALIDPARAMERR; }
    let name = unsafe { cstr_to_string(sz_file_name) };
    let app_handle = h_application as usize as u32;
    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let app = match ctx.get_app_mut(app_handle) {
                    Some(a) => a,
                    None => return SAR_INVALIDHANDLEERR,
                };
                if app.files.remove(&name).is_none() {
                    return SAR_READFILEERR;
                }
                SAR_OK
            }
        }
    })
}

/// SKF_EnumFiles：枚举文件（'\0' 分隔）
pub fn skf_enum_files(
    h_application: *mut std::os::raw::c_void,
    sz_file_list: *mut i8,
    pul_size: *mut u32,
) -> u32 {
    if pul_size.is_null() { return SAR_INVALIDPARAMERR; }
    let app_handle = h_application as usize as u32;
    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let app = match ctx.get_app(app_handle) {
                    Some(a) => a,
                    None => return SAR_INVALIDHANDLEERR,
                };
                let names: Vec<String> = app.files.keys().cloned().collect();
                let needed = names.iter().map(|n| n.len() + 1).sum::<usize>() + 1;
                let buf_size = unsafe { *pul_size as usize };
                if sz_file_list.is_null() || buf_size < needed {
                    unsafe { *pul_size = needed as u32; }
                    return if sz_file_list.is_null() { SAR_OK } else { SAR_INDATALENERR };
                }
                let mut offset = 0usize;
                unsafe {
                    let buf = std::slice::from_raw_parts_mut(sz_file_list as *mut u8, needed);
                    for name in &names {
                        let bytes = name.as_bytes();
                        buf[offset..offset + bytes.len()].copy_from_slice(bytes);
                        offset += bytes.len();
                        buf[offset] = 0;
                        offset += 1;
                    }
                    buf[offset] = 0;
                    *pul_size = needed as u32;
                }
                SAR_OK
            }
        }
    })
}

/// SKF_GetFileInfo：获取文件属性
pub fn skf_get_file_info(
    h_application: *mut std::os::raw::c_void,
    sz_file_name: *const i8,
    p_file_info: *mut FILEATTRIBUTE,
) -> u32 {
    if sz_file_name.is_null() || p_file_info.is_null() { return SAR_INVALIDPARAMERR; }
    let name = unsafe { cstr_to_string(sz_file_name) };
    let app_handle = h_application as usize as u32;
    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let app = match ctx.get_app(app_handle) {
                    Some(a) => a,
                    None => return SAR_INVALIDHANDLEERR,
                };
                match app.files.get(&name) {
                    Some(f) => {
                        let mut attr = FILEATTRIBUTE::default();
                        copy_str_to_buf(&name, &mut attr.FileName);
                        attr.FileSize = f.size;
                        attr.ReadRights = f.read_rights;
                        attr.WriteRights = f.write_rights;
                        unsafe { *p_file_info = attr; }
                        SAR_OK
                    }
                    None => SAR_READFILEERR,
                }
            }
        }
    })
}

/// SKF_ReadFile：读取文件内容
pub fn skf_read_file(
    h_application: *mut std::os::raw::c_void,
    sz_file_name: *const i8,
    ul_offset: u32,
    ul_size: u32,
    pb_out: *mut u8,
    pul_out_len: *mut u32,
) -> u32 {
    if sz_file_name.is_null() || pul_out_len.is_null() { return SAR_INVALIDPARAMERR; }
    let name = unsafe { cstr_to_string(sz_file_name) };
    let app_handle = h_application as usize as u32;
    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let app = match ctx.get_app(app_handle) {
                    Some(a) => a,
                    None => return SAR_INVALIDHANDLEERR,
                };
                match app.files.get(&name) {
                    Some(f) => {
                        let offset = ul_offset as usize;
                        if offset >= f.data.len() {
                            unsafe { *pul_out_len = 0; }
                            return SAR_OK;
                        }
                        let available = f.data.len() - offset;
                        let read_len = (ul_size as usize).min(available);
                        if pb_out.is_null() {
                            unsafe { *pul_out_len = read_len as u32; }
                            return SAR_OK;
                        }
                        unsafe {
                            let buf = std::slice::from_raw_parts_mut(pb_out, read_len);
                            buf.copy_from_slice(&f.data[offset..offset + read_len]);
                            *pul_out_len = read_len as u32;
                        }
                        SAR_OK
                    }
                    None => SAR_READFILEERR,
                }
            }
        }
    })
}

/// SKF_WriteFile：写入文件内容
pub fn skf_write_file(
    h_application: *mut std::os::raw::c_void,
    sz_file_name: *const i8,
    ul_offset: u32,
    pb_data: *const u8,
    ul_size: u32,
) -> u32 {
    if sz_file_name.is_null() || pb_data.is_null() { return SAR_INVALIDPARAMERR; }
    let name = unsafe { cstr_to_string(sz_file_name) };
    let data = unsafe { std::slice::from_raw_parts(pb_data, ul_size as usize).to_vec() };
    let app_handle = h_application as usize as u32;
    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let app = match ctx.get_app_mut(app_handle) {
                    Some(a) => a,
                    None => return SAR_INVALIDHANDLEERR,
                };
                match app.files.get_mut(&name) {
                    Some(f) => {
                        let offset = ul_offset as usize;
                        let end = offset + data.len();
                        if end > f.data.len() {
                            f.data.resize(end, 0);
                        }
                        f.data[offset..end].copy_from_slice(&data);
                        SAR_OK
                    }
                    None => SAR_WRITEFILEERR,
                }
            }
        }
    })
}

// ──────── 证书 + 公钥 ────────

/// SKF_ImportCertificate：将证书 DER 存入容器
/// bSignFlag: true=签名证书, false=加密证书
pub fn skf_import_certificate(
    h_container: *mut std::os::raw::c_void,
    b_sign_flag: i32,
    pb_cert: *const u8,
    ul_cert_len: u32,
) -> u32 {
    if pb_cert.is_null() { return SAR_INVALIDPARAMERR; }
    let cert_der = unsafe { std::slice::from_raw_parts(pb_cert, ul_cert_len as usize).to_vec() };
    let handle = h_container as usize as u32;
    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let container = match ctx.get_container_mut(handle) {
                    Some(c) => c,
                    None => return SAR_INVALIDHANDLEERR,
                };
                if b_sign_flag != 0 {
                    container.sign_cert = Some(cert_der);
                } else {
                    container.enc_cert = Some(cert_der);
                }
                SAR_OK
            }
        }
    })
}

/// SKF_ExportCertificate：从容器导出证书 DER
pub fn skf_export_certificate(
    h_container: *mut std::os::raw::c_void,
    b_sign_flag: i32,
    pb_cert: *mut u8,
    pul_cert_len: *mut u32,
) -> u32 {
    if pul_cert_len.is_null() { return SAR_INVALIDPARAMERR; }
    let handle = h_container as usize as u32;
    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let container = match ctx.get_container(handle) {
                    Some(c) => c,
                    None => return SAR_INVALIDHANDLEERR,
                };
                let cert_opt = if b_sign_flag != 0 {
                    container.sign_cert.as_deref()
                } else {
                    container.enc_cert.as_deref()
                };
                match cert_opt {
                    None => SAR_CERTNOTFOUNDERR,
                    Some(der) => {
                        let len = der.len();
                        unsafe {
                            if pb_cert.is_null() || (*pul_cert_len as usize) < len {
                                *pul_cert_len = len as u32;
                                return if pb_cert.is_null() { SAR_OK } else { SAR_INDATALENERR };
                            }
                            std::ptr::copy_nonoverlapping(der.as_ptr(), pb_cert, len);
                            *pul_cert_len = len as u32;
                        }
                        SAR_OK
                    }
                }
            }
        }
    })
}

/// SKF_ExportPublicKey：从容器导出 ECC 公钥 Blob
/// bSignFlag: true=签名公钥, false=加密公钥
pub fn skf_export_public_key(
    h_container: *mut std::os::raw::c_void,
    b_sign_flag: i32,
    pb_blob: *mut u8,
    pul_blob_len: *mut u32,
) -> u32 {
    if pul_blob_len.is_null() { return SAR_INVALIDPARAMERR; }
    let blob_size = std::mem::size_of::<ECCPUBLICKEYBLOB>() as u32;
    let handle = h_container as usize as u32;

    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let container = match ctx.get_container(handle) {
                    Some(c) => c,
                    None => return SAR_INVALIDHANDLEERR,
                };
                let keypair_opt = if b_sign_flag != 0 {
                    container.sign_keypair.as_ref()
                } else {
                    container.enc_keypair.as_ref()
                };
                match keypair_opt {
                    None => SAR_KEYNOTFOUNDERR,
                    Some((_, pub_key)) => {
                        let blob = crate::crypto::sm2_ops::pub_key_to_blob(pub_key);
                        unsafe {
                            if pb_blob.is_null() || (*pul_blob_len as usize) < std::mem::size_of::<ECCPUBLICKEYBLOB>() {
                                *pul_blob_len = blob_size;
                                return if pb_blob.is_null() { SAR_OK } else { SAR_INDATALENERR };
                            }
                            std::ptr::copy_nonoverlapping(
                                &blob as *const ECCPUBLICKEYBLOB as *const u8,
                                pb_blob,
                                std::mem::size_of::<ECCPUBLICKEYBLOB>(),
                            );
                            *pul_blob_len = blob_size;
                        }
                        SAR_OK
                    }
                }
            }
        }
    })
}
