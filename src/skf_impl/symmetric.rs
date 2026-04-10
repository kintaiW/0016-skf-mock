// 对称密码服务实现
// SKF_SetSymmKey / SKF_EncryptInit / SKF_Encrypt / SKF_DecryptInit / SKF_Decrypt

use crate::error_code::*;
use crate::key_mgr::{SymKeyEntry, CipherParam};
use crate::types::BLOCKCIPHERPARAM;
use crate::crypto::sm4_ops;
use super::device::with_device;

/// SKF_SetSymmKey：设置对称密钥，返回密钥句柄
pub fn skf_set_symm_key(
    _h_dev: *mut std::os::raw::c_void,
    pb_key: *const u8,
    ul_alg_id: u32,
    ph_key: *mut *mut std::os::raw::c_void,
) -> u32 {
    if pb_key.is_null() || ph_key.is_null() { return SAR_INVALIDPARAMERR; }

    // 仅支持 SM4
    if ul_alg_id != SGD_SM4_ECB && ul_alg_id != SGD_SM4_CBC {
        return SAR_NOTSUPPORTYETERR;
    }

    let key_bytes_slice = unsafe { std::slice::from_raw_parts(pb_key, 16) };
    let mut key_bytes = [0u8; 16];
    key_bytes.copy_from_slice(key_bytes_slice);

    let entry = SymKeyEntry { key_bytes, alg_id: ul_alg_id, cipher_param: None };

    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let handle = ctx.alloc_key_handle(entry);
                unsafe { *ph_key = handle as usize as *mut _; }
                log::debug!("SKF_SetSymmKey: 密钥句柄 0x{:08X}", handle);
                SAR_OK
            }
        }
    })
}

/// SKF_EncryptInit：初始化加密上下文（设置 IV 和填充类型）
pub fn skf_encrypt_init(h_key: *mut std::os::raw::c_void, param: BLOCKCIPHERPARAM) -> u32 {
    let handle = h_key as usize as u32;
    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let entry = match ctx.key_handles.get_mut(&handle) {
                    Some(e) => e,
                    None => return SAR_INVALIDHANDLEERR,
                };
                // 提取 IV（取前 IVLen 字节，最多 16 字节）
                let iv_len = (param.IVLen as usize).min(16);
                let mut iv = [0u8; 16];
                iv[..iv_len].copy_from_slice(&param.IV[..iv_len]);
                entry.cipher_param = Some(CipherParam {
                    iv,
                    padding_type: param.PaddingType,
                    for_encrypt: true,
                });
                SAR_OK
            }
        }
    })
}

/// SKF_Encrypt：执行单次加密
pub fn skf_encrypt(
    h_key: *mut std::os::raw::c_void,
    pb_data: *const u8,
    ul_data_len: u32,
    pb_enc: *mut u8,
    pul_enc_len: *mut u32,
) -> u32 {
    if pb_data.is_null() || pul_enc_len.is_null() { return SAR_INVALIDPARAMERR; }
    let data = unsafe { std::slice::from_raw_parts(pb_data, ul_data_len as usize) };
    let handle = h_key as usize as u32;

    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let entry = match ctx.key_handles.get(&handle) {
                    Some(e) => e,
                    None => return SAR_INVALIDHANDLEERR,
                };
                let (alg_id, param) = (entry.alg_id, entry.cipher_param.clone());
                let param = match param {
                    Some(p) => p,
                    None => return SAR_NOTINITIALIZEERR,
                };
                let padding = param.padding_type == 1;
                let key = entry.key_bytes;

                let encrypted = match alg_id {
                    SGD_SM4_CBC => sm4_ops::sm4_cbc_encrypt(&key, &param.iv, data, padding),
                    SGD_SM4_ECB => sm4_ops::sm4_ecb_encrypt(&key, data, padding),
                    _ => return SAR_NOTSUPPORTYETERR,
                };

                let enc_len = encrypted.len();
                unsafe {
                    if pb_enc.is_null() || (*pul_enc_len as usize) < enc_len {
                        *pul_enc_len = enc_len as u32;
                        return if pb_enc.is_null() { SAR_OK } else { SAR_INDATALENERR };
                    }
                    std::ptr::copy_nonoverlapping(encrypted.as_ptr(), pb_enc, enc_len);
                    *pul_enc_len = enc_len as u32;
                }
                SAR_OK
            }
        }
    })
}

/// SKF_DecryptInit：初始化解密上下文
pub fn skf_decrypt_init(h_key: *mut std::os::raw::c_void, param: BLOCKCIPHERPARAM) -> u32 {
    let handle = h_key as usize as u32;
    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let entry = match ctx.key_handles.get_mut(&handle) {
                    Some(e) => e,
                    None => return SAR_INVALIDHANDLEERR,
                };
                let iv_len = (param.IVLen as usize).min(16);
                let mut iv = [0u8; 16];
                iv[..iv_len].copy_from_slice(&param.IV[..iv_len]);
                entry.cipher_param = Some(CipherParam {
                    iv,
                    padding_type: param.PaddingType,
                    for_encrypt: false,
                });
                SAR_OK
            }
        }
    })
}

/// SKF_Decrypt：执行单次解密
pub fn skf_decrypt(
    h_key: *mut std::os::raw::c_void,
    pb_data: *const u8,
    ul_data_len: u32,
    pb_dec: *mut u8,
    pul_dec_len: *mut u32,
) -> u32 {
    if pb_data.is_null() || pul_dec_len.is_null() { return SAR_INVALIDPARAMERR; }
    let data = unsafe { std::slice::from_raw_parts(pb_data, ul_data_len as usize) };
    let handle = h_key as usize as u32;

    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let entry = match ctx.key_handles.get(&handle) {
                    Some(e) => e,
                    None => return SAR_INVALIDHANDLEERR,
                };
                let (alg_id, param) = (entry.alg_id, entry.cipher_param.clone());
                let param = match param {
                    Some(p) => p,
                    None => return SAR_NOTINITIALIZEERR,
                };
                let padding = param.padding_type == 1;
                let key = entry.key_bytes;

                let decrypted = match alg_id {
                    SGD_SM4_CBC => sm4_ops::sm4_cbc_decrypt(&key, &param.iv, data, padding),
                    SGD_SM4_ECB => sm4_ops::sm4_ecb_decrypt(&key, data, padding),
                    _ => return SAR_NOTSUPPORTYETERR,
                };

                match decrypted {
                    None => SAR_INDATAERR,
                    Some(plain) => {
                        let len = plain.len();
                        unsafe {
                            if pb_dec.is_null() || (*pul_dec_len as usize) < len {
                                *pul_dec_len = len as u32;
                                return if pb_dec.is_null() { SAR_OK } else { SAR_INDATALENERR };
                            }
                            std::ptr::copy_nonoverlapping(plain.as_ptr(), pb_dec, len);
                            *pul_dec_len = len as u32;
                        }
                        SAR_OK
                    }
                }
            }
        }
    })
}

/// SKF_DestroyKey：销毁密钥句柄
pub fn skf_destroy_key(h_key: *mut std::os::raw::c_void) -> u32 {
    let handle = h_key as usize as u32;
    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                if ctx.free_key_handle(handle) { SAR_OK } else { SAR_INVALIDHANDLEERR }
            }
        }
    })
}
