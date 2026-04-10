// 密码服务 FFI 导出
// 对称加密：SKF_SetSymmKey / SKF_EncryptInit / SKF_Encrypt / SKF_DecryptInit / SKF_Decrypt / SKF_DestroyKey
// 哈希：SKF_DigestInit / SKF_Digest / SKF_DigestUpdate / SKF_DigestFinal / SKF_CloseHash
// MAC（桩）：SKF_MACInit / SKF_MAC / SKF_MACUpdate / SKF_MACFinal / SKF_CloseMac

use std::os::raw::c_void;
use crate::types::{BLOCKCIPHERPARAM, ECCPUBLICKEYBLOB};
use crate::skf_impl::{symmetric, hash};
use crate::error_code::SAR_NOTSUPPORTYETERR;

// ──────── 对称加密 ────────

#[no_mangle]
pub extern "C" fn SKF_SetSymmKey(
    hDev: *mut c_void,
    pbKey: *const u8,
    ulAlgID: u32,
    phKey: *mut *mut c_void,
) -> u32 {
    symmetric::skf_set_symm_key(hDev, pbKey, ulAlgID, phKey)
}

#[no_mangle]
pub extern "C" fn SKF_EncryptInit(
    hKey: *mut c_void,
    EncryptParam: BLOCKCIPHERPARAM,
) -> u32 {
    symmetric::skf_encrypt_init(hKey, EncryptParam)
}

#[no_mangle]
pub extern "C" fn SKF_Encrypt(
    hKey: *mut c_void,
    pbData: *const u8,
    ulDataLen: u32,
    pbEncryptedData: *mut u8,
    pulEncryptedLen: *mut u32,
) -> u32 {
    symmetric::skf_encrypt(hKey, pbData, ulDataLen, pbEncryptedData, pulEncryptedLen)
}

#[no_mangle]
pub extern "C" fn SKF_EncryptUpdate(
    hKey: *mut c_void,
    pbData: *const u8,
    ulDataLen: u32,
    pbEncryptedData: *mut u8,
    pulEncryptedLen: *mut u32,
) -> u32 {
    // Reason: EncryptUpdate 在单次 Encrypt 场景下等同于 Encrypt（流式接口简化处理）
    symmetric::skf_encrypt(hKey, pbData, ulDataLen, pbEncryptedData, pulEncryptedLen)
}

#[no_mangle]
pub extern "C" fn SKF_EncryptFinal(
    hKey: *mut c_void,
    pbEncryptedData: *mut u8,
    pulEncryptedDataLen: *mut u32,
) -> u32 {
    // Reason: Mock 不支持流式加密分块，EncryptFinal 返回空（0字节剩余）
    if pulEncryptedDataLen.is_null() { return crate::error_code::SAR_INVALIDPARAMERR; }
    let _ = (hKey, pbEncryptedData);
    unsafe { *pulEncryptedDataLen = 0; }
    crate::error_code::SAR_OK
}

#[no_mangle]
pub extern "C" fn SKF_DecryptInit(
    hKey: *mut c_void,
    DecryptParam: BLOCKCIPHERPARAM,
) -> u32 {
    symmetric::skf_decrypt_init(hKey, DecryptParam)
}

#[no_mangle]
pub extern "C" fn SKF_Decrypt(
    hKey: *mut c_void,
    pbEncryptedData: *const u8,
    ulEncryptedLen: u32,
    pbData: *mut u8,
    pulDataLen: *mut u32,
) -> u32 {
    symmetric::skf_decrypt(hKey, pbEncryptedData, ulEncryptedLen, pbData, pulDataLen)
}

#[no_mangle]
pub extern "C" fn SKF_DecryptUpdate(
    hKey: *mut c_void,
    pbEncryptedData: *const u8,
    ulEncryptedLen: u32,
    pbData: *mut u8,
    pulDataLen: *mut u32,
) -> u32 {
    symmetric::skf_decrypt(hKey, pbEncryptedData, ulEncryptedLen, pbData, pulDataLen)
}

#[no_mangle]
pub extern "C" fn SKF_DecryptFinal(
    hKey: *mut c_void,
    pbDecryptedData: *mut u8,
    pulDecryptedDataLen: *mut u32,
) -> u32 {
    if pulDecryptedDataLen.is_null() { return crate::error_code::SAR_INVALIDPARAMERR; }
    let _ = (hKey, pbDecryptedData);
    unsafe { *pulDecryptedDataLen = 0; }
    crate::error_code::SAR_OK
}

#[no_mangle]
pub extern "C" fn SKF_DestroyKey(hKey: *mut c_void) -> u32 {
    symmetric::skf_destroy_key(hKey)
}

// ──────── 哈希 ────────

#[no_mangle]
pub extern "C" fn SKF_DigestInit(
    hDev: *mut c_void,
    ulAlgID: u32,
    pPubKey: *const ECCPUBLICKEYBLOB,
    pbID: *const u8,
    ulIDLen: u32,
    phHash: *mut *mut c_void,
) -> u32 {
    hash::skf_digest_init(hDev, ulAlgID, pPubKey, pbID, ulIDLen, phHash)
}

#[no_mangle]
pub extern "C" fn SKF_Digest(
    hHash: *mut c_void,
    pbData: *const u8,
    ulDataLen: u32,
    pbDigest: *mut u8,
    pulDigestLen: *mut u32,
) -> u32 {
    hash::skf_digest(hHash, pbData, ulDataLen, pbDigest, pulDigestLen)
}

#[no_mangle]
pub extern "C" fn SKF_DigestUpdate(
    hHash: *mut c_void,
    pbData: *const u8,
    ulDataLen: u32,
) -> u32 {
    hash::skf_digest_update(hHash, pbData, ulDataLen)
}

#[no_mangle]
pub extern "C" fn SKF_DigestFinal(
    hHash: *mut c_void,
    pHashData: *mut u8,
    pulHashLen: *mut u32,
) -> u32 {
    hash::skf_digest_final(hHash, pHashData, pulHashLen)
}

#[no_mangle]
pub extern "C" fn SKF_CloseHash(hHash: *mut c_void) -> u32 {
    hash::skf_close_hash(hHash)
}

// ──────── MAC（桩） ────────

#[no_mangle]
pub extern "C" fn SKF_MACInit(
    hKey: *mut c_void,
    pMacParam: *const BLOCKCIPHERPARAM,
    phMac: *mut *mut c_void,
) -> u32 {
    let _ = (hKey, pMacParam, phMac);
    SAR_NOTSUPPORTYETERR
}

#[no_mangle]
pub extern "C" fn SKF_MAC(
    hMac: *mut c_void,
    pbData: *const u8,
    ulDataLen: u32,
    pbMac: *mut u8,
    pulMacLen: *mut u32,
) -> u32 {
    let _ = (hMac, pbData, ulDataLen, pbMac, pulMacLen);
    SAR_NOTSUPPORTYETERR
}

#[no_mangle]
pub extern "C" fn SKF_MACUpdate(
    hMac: *mut c_void,
    pbData: *const u8,
    ulDataLen: u32,
) -> u32 {
    let _ = (hMac, pbData, ulDataLen);
    SAR_NOTSUPPORTYETERR
}

#[no_mangle]
pub extern "C" fn SKF_MACFinal(
    hMac: *mut c_void,
    pbMac: *mut u8,
    pulMacLen: *mut u32,
) -> u32 {
    let _ = (hMac, pbMac, pulMacLen);
    SAR_NOTSUPPORTYETERR
}

#[no_mangle]
pub extern "C" fn SKF_CloseMac(hMac: *mut c_void) -> u32 {
    let _ = hMac;
    SAR_NOTSUPPORTYETERR
}
