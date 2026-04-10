// ECC 密码服务实现
// SKF_GenECCKeyPair / SKF_ImportECCKeyPair
// SKF_ECCSignData / SKF_ECCVerify
// SKF_ExtECCEncrypt / SKF_ExtECCDecrypt
// SKF_ExtECCSign / SKF_ExtECCVerify
// SKF_ECCExportSessionKey / SKF_ImportSessionKey

use crate::error_code::*;
use crate::types::{ECCPUBLICKEYBLOB, ECCCIPHERBLOB, ECCSIGNATUREBLOB, ECCPRIVATEKEYBLOB, ENVELOPEDKEYBLOB};
use crate::key_mgr::{SymKeyEntry};
use crate::crypto::sm2_ops;
use super::device::with_device;

/// SKF_GenECCKeyPair：生成 ECC 密钥对并存入容器
/// ulAlgId: SGD_SM2_1=签名密钥, SGD_SM2_3=加密密钥
pub fn skf_gen_ecc_keypair(
    h_container: *mut std::os::raw::c_void,
    ul_alg_id: u32,
    p_blob: *mut ECCPUBLICKEYBLOB,
) -> u32 {
    if p_blob.is_null() { return SAR_INVALIDPARAMERR; }

    let is_sign = match ul_alg_id {
        SGD_SM2_1 => true,
        SGD_SM2_3 => false,
        _ => return SAR_KEYUSAGEERR,
    };
    let handle = h_container as usize as u32;

    let (priv_key, pub_key) = sm2_ops::sm2_generate_keypair();
    let blob = sm2_ops::pub_key_to_blob(&pub_key);

    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let container = match ctx.get_container_mut(handle) {
                    Some(c) => c,
                    None => return SAR_INVALIDHANDLEERR,
                };
                if is_sign {
                    container.sign_keypair = Some((priv_key, pub_key));
                } else {
                    container.enc_keypair = Some((priv_key, pub_key));
                }
                unsafe { *p_blob = blob; }
                log::debug!("SKF_GenECCKeyPair: 生成密钥对（{}）", if is_sign { "签名" } else { "加密" });
                SAR_OK
            }
        }
    })
}

/// SKF_ImportECCKeyPair：导入 SM2 加密密钥对（通过数字信封）
/// Reason: 加密私钥通过 ENVELOPEDKEYBLOB 中的 SM2 加密的对称密钥传输，保护私钥安全
pub fn skf_import_ecc_keypair(
    h_container: *mut std::os::raw::c_void,
    p_enveloped: *mut ENVELOPEDKEYBLOB,
) -> u32 {
    if p_enveloped.is_null() { return SAR_INVALIDPARAMERR; }
    let handle = h_container as usize as u32;

    // 从信封中提取公钥（直接存储）
    let (pub_key, enc_keypair_opt) = unsafe {
        let blob = &*p_enveloped;
        let pub_key = sm2_ops::blob_to_pub_key(&blob.PubKey);
        // Mock：直接存储公钥，私钥从信封解密（简化：此处不实际解密私钥）
        // Reason: 数字信封导入私钥需要容器自身的加密私钥解密信封，Mock 中仅存公钥
        (pub_key, None::<([u8; 32], [u8; 65])>)
    };

    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let container = match ctx.get_container_mut(handle) {
                    Some(c) => c,
                    None => return SAR_INVALIDHANDLEERR,
                };
                // 存储加密公钥（私钥在 Mock 中不实际解密，仅公钥有效）
                if let Some(kp) = enc_keypair_opt {
                    container.enc_keypair = Some(kp);
                } else {
                    // 只有公钥时，用零私钥占位
                    container.enc_keypair = Some(([0u8; 32], pub_key));
                }
                SAR_OK
            }
        }
    })
}

/// SKF_ECCSignData：用容器签名私钥对数据进行 SM2 签名
pub fn skf_ecc_sign_data(
    h_container: *mut std::os::raw::c_void,
    pb_data: *const u8,
    ul_data_len: u32,
    p_signature: *mut ECCSIGNATUREBLOB,
) -> u32 {
    if pb_data.is_null() || p_signature.is_null() { return SAR_INVALIDPARAMERR; }
    let data = unsafe { std::slice::from_raw_parts(pb_data, ul_data_len as usize) };
    let handle = h_container as usize as u32;

    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let container = match ctx.get_container(handle) {
                    Some(c) => c,
                    None => return SAR_INVALIDHANDLEERR,
                };
                let (priv_key, _) = match container.sign_keypair.as_ref() {
                    Some(kp) => kp,
                    None => return SAR_KEYNOTFOUNDERR,
                };
                match sm2_ops::sm2_sign(priv_key, data) {
                    Some(sig_64) => {
                        unsafe { *p_signature = sm2_ops::sig_to_blob(&sig_64); }
                        SAR_OK
                    }
                    None => SAR_FAIL,
                }
            }
        }
    })
}

/// SKF_ECCVerify：用外部公钥 Blob 验证 SM2 签名
pub fn skf_ecc_verify(
    _h_dev: *mut std::os::raw::c_void,
    p_pub_key: *const ECCPUBLICKEYBLOB,
    pb_data: *const u8,
    ul_data_len: u32,
    p_signature: *const ECCSIGNATUREBLOB,
) -> u32 {
    if p_pub_key.is_null() || pb_data.is_null() || p_signature.is_null() {
        return SAR_INVALIDPARAMERR;
    }
    let pub_key = unsafe { sm2_ops::blob_to_pub_key(&*p_pub_key) };
    let data = unsafe { std::slice::from_raw_parts(pb_data, ul_data_len as usize) };
    let sig = unsafe { sm2_ops::blob_to_sig(&*p_signature) };

    if sm2_ops::sm2_verify(&pub_key, data, &sig) {
        SAR_OK
    } else {
        SAR_FAIL
    }
}

/// SKF_ECCExportSessionKey：生成随机 SM4 会话密钥，用外部 ECC 公钥加密后输出
pub fn skf_ecc_export_session_key(
    _h_container: *mut std::os::raw::c_void,
    ul_alg_id: u32,
    p_pub_key: *const ECCPUBLICKEYBLOB,
    p_cipher_blob: *mut ECCCIPHERBLOB,
    ph_session_key: *mut *mut std::os::raw::c_void,
) -> u32 {
    if p_pub_key.is_null() || p_cipher_blob.is_null() || ph_session_key.is_null() {
        return SAR_INVALIDPARAMERR;
    }

    // 生成随机 SM4 密钥
    use rand::RngCore;
    let mut sm4_key = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut sm4_key);

    let pub_key = unsafe { sm2_ops::blob_to_pub_key(&*p_pub_key) };

    // SM2 加密 SM4 密钥
    let cipher_bytes = match sm2_ops::sm2_encrypt(&pub_key, &sm4_key) {
        Some(c) => c,
        None => return SAR_FAIL,
    };

    // 转换为 ECCCIPHERBLOB
    let blob = match sm2_ops::cipher_bytes_to_blob(&cipher_bytes) {
        Some(b) => b,
        None => return SAR_FAIL,
    };
    unsafe { *p_cipher_blob = blob; }

    // 存储会话密钥，返回句柄
    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let entry = SymKeyEntry {
                    key_bytes: sm4_key,
                    alg_id: ul_alg_id,
                    cipher_param: None,
                };
                let key_handle = ctx.alloc_key_handle(entry);
                unsafe { *ph_session_key = key_handle as usize as *mut _; }
                log::debug!("SKF_ECCExportSessionKey: 会话密钥句柄 0x{:08X}", key_handle);
                SAR_OK
            }
        }
    })
}

/// SKF_ImportSessionKey：用容器加密私钥解密 SM2 密文，恢复 SM4 会话密钥
pub fn skf_import_session_key(
    h_container: *mut std::os::raw::c_void,
    ul_alg_id: u32,
    pb_wrapped: *const u8,
    ul_wrapped_len: u32,
    ph_key: *mut *mut std::os::raw::c_void,
) -> u32 {
    if pb_wrapped.is_null() || ph_key.is_null() { return SAR_INVALIDPARAMERR; }
    let wrapped = unsafe { std::slice::from_raw_parts(pb_wrapped, ul_wrapped_len as usize) };
    let handle = h_container as usize as u32;

    with_device(|res| {
        match res {
            Err(e) => e,
            Ok(ctx) => {
                let container = match ctx.get_container(handle) {
                    Some(c) => c,
                    None => return SAR_INVALIDHANDLEERR,
                };
                let (priv_key, _) = match container.enc_keypair.as_ref() {
                    Some(kp) => kp,
                    None => return SAR_KEYNOTFOUNDERR,
                };
                let priv_key = *priv_key;
                drop(container);

                // SM2 解密恢复 SM4 密钥
                let sm4_key_vec = match sm2_ops::sm2_decrypt(&priv_key, wrapped) {
                    Some(k) => k,
                    None => return SAR_FAIL,
                };
                if sm4_key_vec.len() != 16 { return SAR_INDATALENERR; }
                let mut sm4_key = [0u8; 16];
                sm4_key.copy_from_slice(&sm4_key_vec);

                let entry = SymKeyEntry { key_bytes: sm4_key, alg_id: ul_alg_id, cipher_param: None };
                let key_handle = ctx.alloc_key_handle(entry);
                unsafe { *ph_key = key_handle as usize as *mut _; }
                SAR_OK
            }
        }
    })
}

/// SKF_ExtECCEncrypt：用外部 ECC 公钥加密数据
pub fn skf_ext_ecc_encrypt(
    _h_dev: *mut std::os::raw::c_void,
    p_pub_key: *const ECCPUBLICKEYBLOB,
    pb_plain: *const u8,
    ul_plain_len: u32,
    p_cipher: *mut ECCCIPHERBLOB,
) -> u32 {
    if p_pub_key.is_null() || pb_plain.is_null() || p_cipher.is_null() {
        return SAR_INVALIDPARAMERR;
    }
    let pub_key = unsafe { sm2_ops::blob_to_pub_key(&*p_pub_key) };
    let plain = unsafe { std::slice::from_raw_parts(pb_plain, ul_plain_len as usize) };

    match sm2_ops::sm2_encrypt(&pub_key, plain) {
        Some(cipher_bytes) => {
            match sm2_ops::cipher_bytes_to_blob(&cipher_bytes) {
                Some(blob) => {
                    unsafe { *p_cipher = blob; }
                    SAR_OK
                }
                None => SAR_INDATALENERR,
            }
        }
        None => SAR_FAIL,
    }
}

/// SKF_ExtECCDecrypt：用外部 ECC 私钥解密数据
pub fn skf_ext_ecc_decrypt(
    _h_dev: *mut std::os::raw::c_void,
    p_pri_key: *const ECCPRIVATEKEYBLOB,
    p_cipher: *const ECCCIPHERBLOB,
    pb_plain: *mut u8,
    pul_plain_len: *mut u32,
) -> u32 {
    if p_pri_key.is_null() || p_cipher.is_null() || pul_plain_len.is_null() {
        return SAR_INVALIDPARAMERR;
    }
    let priv_key = unsafe { sm2_ops::pri_blob_to_key(&*p_pri_key) };
    let cipher_bytes = unsafe { sm2_ops::blob_to_cipher_bytes(&*p_cipher) };

    match sm2_ops::sm2_decrypt(&priv_key, &cipher_bytes) {
        Some(plain) => {
            unsafe {
                if pb_plain.is_null() || (*pul_plain_len as usize) < plain.len() {
                    *pul_plain_len = plain.len() as u32;
                    return if pb_plain.is_null() { SAR_OK } else { SAR_INDATALENERR };
                }
                std::ptr::copy_nonoverlapping(plain.as_ptr(), pb_plain, plain.len());
                *pul_plain_len = plain.len() as u32;
            }
            SAR_OK
        }
        None => SAR_FAIL,
    }
}

/// SKF_ExtECCSign：用外部 ECC 私钥签名
pub fn skf_ext_ecc_sign(
    _h_dev: *mut std::os::raw::c_void,
    p_pri_key: *const ECCPRIVATEKEYBLOB,
    pb_data: *const u8,
    ul_data_len: u32,
    p_signature: *mut ECCSIGNATUREBLOB,
) -> u32 {
    if p_pri_key.is_null() || pb_data.is_null() || p_signature.is_null() {
        return SAR_INVALIDPARAMERR;
    }
    let priv_key = unsafe { sm2_ops::pri_blob_to_key(&*p_pri_key) };
    let data = unsafe { std::slice::from_raw_parts(pb_data, ul_data_len as usize) };

    match sm2_ops::sm2_sign(&priv_key, data) {
        Some(sig_64) => {
            unsafe { *p_signature = sm2_ops::sig_to_blob(&sig_64); }
            SAR_OK
        }
        None => SAR_FAIL,
    }
}

/// SKF_ExtECCVerify：用外部 ECC 公钥验签
pub fn skf_ext_ecc_verify(
    _h_dev: *mut std::os::raw::c_void,
    p_pub_key: *const ECCPUBLICKEYBLOB,
    pb_data: *const u8,
    ul_data_len: u32,
    p_signature: *const ECCSIGNATUREBLOB,
) -> u32 {
    skf_ecc_verify(_h_dev, p_pub_key, pb_data, ul_data_len, p_signature)
}
