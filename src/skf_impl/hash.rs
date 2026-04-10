// 哈希密码服务实现
// SKF_DigestInit / SKF_Digest / SKF_DigestUpdate / SKF_DigestFinal

use crate::error_code::*;
use crate::key_mgr::HashCtx;
use crate::crypto::{sm2_ops, sm3_ops};
use super::device::with_device;

/// SKF_DigestInit：初始化哈希上下文
/// ul_alg_id: SGD_SM3=0x00000001
/// p_pub_key: 可选，非空时用于 SM2 Z 值计算（SKF_Digest 流程）
/// pb_id: 用户 ID，p_pub_key 非空时使用
/// ul_id_len: 用户 ID 字节长度
pub fn skf_digest_init(
    _h_dev: *mut std::os::raw::c_void,
    ul_alg_id: u32,
    p_pub_key: *const crate::types::ECCPUBLICKEYBLOB,
    pb_id: *const u8,
    ul_id_len: u32,
    ph_hash: *mut *mut std::os::raw::c_void,
) -> u32 {
    if ph_hash.is_null() { return SAR_INVALIDPARAMERR; }

    if ul_alg_id != SGD_SM3 { return SAR_NOTSUPPORTYETERR; }

    // 如果提供了公钥，则在 DigestUpdate 前先计算 Z 值并放入缓冲
    // Reason: SM2 标准要求对消息进行签名时，先用 Z||M 的 SM3 哈希作为输入
    let (pub_key_opt, user_id) = if p_pub_key.is_null() {
        (None, Vec::new())
    } else {
        let pk = unsafe { sm2_ops::blob_to_pub_key(&*p_pub_key) };
        let uid = if pb_id.is_null() || ul_id_len == 0 {
            sm2_ops::DEFAULT_USER_ID.to_vec()
        } else {
            unsafe { std::slice::from_raw_parts(pb_id, ul_id_len as usize).to_vec() }
        };
        (Some(pk), uid)
    };

    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                // 预计算 Z 值，写入初始缓冲
                // Reason: SM2 签名哈希 = SM3(Z || message)，Z 在 DigestInit 时就确定
                let initial_data = if let Some(ref pk) = pub_key_opt {
                    let z = sm3_ops::sm2_z_value(pk, &user_id);
                    z.to_vec()
                } else {
                    Vec::new()
                };

                let hash_ctx = HashCtx {
                    buffer: initial_data,
                    pub_key: pub_key_opt,
                    user_id,
                };
                let handle = ctx.alloc_hash_handle(hash_ctx);
                unsafe { *ph_hash = handle as usize as *mut _; }
                log::debug!("SKF_DigestInit: 哈希句柄 0x{:08X}", handle);
                SAR_OK
            }
        }
    })
}

/// SKF_DigestUpdate：追加数据到哈希缓冲
pub fn skf_digest_update(
    h_hash: *mut std::os::raw::c_void,
    pb_data: *const u8,
    ul_data_len: u32,
) -> u32 {
    if pb_data.is_null() { return SAR_INVALIDPARAMERR; }
    let data = unsafe { std::slice::from_raw_parts(pb_data, ul_data_len as usize) };
    let handle = h_hash as usize as u32;

    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let hash_ctx = match ctx.hash_handles.get_mut(&handle) {
                    Some(h) => h,
                    None => return SAR_INVALIDHANDLEERR,
                };
                hash_ctx.buffer.extend_from_slice(data);
                SAR_OK
            }
        }
    })
}

/// SKF_DigestFinal：完成哈希计算，输出结果
pub fn skf_digest_final(
    h_hash: *mut std::os::raw::c_void,
    pb_digest: *mut u8,
    pul_digest_len: *mut u32,
) -> u32 {
    if pul_digest_len.is_null() { return SAR_INVALIDPARAMERR; }
    let handle = h_hash as usize as u32;

    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let hash_ctx = match ctx.hash_handles.get(&handle) {
                    Some(h) => h,
                    None => return SAR_INVALIDHANDLEERR,
                };

                let digest = sm3_ops::sm3_digest(&hash_ctx.buffer);
                let digest_len = digest.len(); // 32 字节

                unsafe {
                    if pb_digest.is_null() || (*pul_digest_len as usize) < digest_len {
                        *pul_digest_len = digest_len as u32;
                        return if pb_digest.is_null() { SAR_OK } else { SAR_INDATALENERR };
                    }
                    std::ptr::copy_nonoverlapping(digest.as_ptr(), pb_digest, digest_len);
                    *pul_digest_len = digest_len as u32;
                }
                SAR_OK
            }
        }
    })
}

/// SKF_Digest：单次哈希（含 Z 值，SKF 标准 SM2 签名前置步骤）
/// 等价于 DigestInit(有公钥) + DigestUpdate(data) + DigestFinal
pub fn skf_digest(
    h_hash: *mut std::os::raw::c_void,
    pb_data: *const u8,
    ul_data_len: u32,
    pb_digest: *mut u8,
    pul_digest_len: *mut u32,
) -> u32 {
    if pb_data.is_null() || pul_digest_len.is_null() { return SAR_INVALIDPARAMERR; }
    let data = unsafe { std::slice::from_raw_parts(pb_data, ul_data_len as usize) };
    let handle = h_hash as usize as u32;

    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let hash_ctx = match ctx.hash_handles.get_mut(&handle) {
                    Some(h) => h,
                    None => return SAR_INVALIDHANDLEERR,
                };

                // 追加本次数据
                hash_ctx.buffer.extend_from_slice(data);

                let digest = sm3_ops::sm3_digest(&hash_ctx.buffer);
                let digest_len = digest.len();

                unsafe {
                    if pb_digest.is_null() || (*pul_digest_len as usize) < digest_len {
                        *pul_digest_len = digest_len as u32;
                        return if pb_digest.is_null() { SAR_OK } else { SAR_INDATALENERR };
                    }
                    std::ptr::copy_nonoverlapping(digest.as_ptr(), pb_digest, digest_len);
                    *pul_digest_len = digest_len as u32;
                }
                SAR_OK
            }
        }
    })
}

/// SKF_CloseHash：销毁哈希句柄
pub fn skf_close_hash(h_hash: *mut std::os::raw::c_void) -> u32 {
    let handle = h_hash as usize as u32;
    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                if ctx.hash_handles.remove(&handle).is_some() {
                    SAR_OK
                } else {
                    SAR_INVALIDHANDLEERR
                }
            }
        }
    })
}
