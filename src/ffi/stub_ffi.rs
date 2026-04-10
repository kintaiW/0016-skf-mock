// 桩函数 FFI 导出
// RSA 相关：SKF_GenRSAKeyPair / SKF_RSASignData / SKF_RSAVerify / SKF_RSAExportSessionKey
//           SKF_ExtRSAPubKeyOperation / SKF_ExtRSAPriKeyOperation
// 密钥协商：SKF_GenerateAgreementDataWithECC / SKF_GenerateAgreementDataAndKeyWithECC
//           SKF_GenerateKeyWithECC
// Reason: Mock 仅支持 SM 算法族，RSA 和密钥协商不实现，返回不支持错误

use std::os::raw::c_void;
use crate::error_code::SAR_NOTSUPPORTYETERR;

// ──────── RSA ────────

#[no_mangle]
pub extern "C" fn SKF_GenRSAKeyPair(
    hContainer: *mut c_void,
    ulBitsLen: u32,
    pBlob: *mut c_void,
) -> u32 {
    let _ = (hContainer, ulBitsLen, pBlob);
    SAR_NOTSUPPORTYETERR
}

#[no_mangle]
pub extern "C" fn SKF_ImportRSAKeyPair(
    hContainer: *mut c_void,
    ulSymAlgID: u32,
    pbWrappedKey: *const u8,
    ulWrappedKeyLen: u32,
    pbEncryptedData: *const u8,
    ulEncryptedDataLen: u32,
) -> u32 {
    let _ = (hContainer, ulSymAlgID, pbWrappedKey, ulWrappedKeyLen, pbEncryptedData, ulEncryptedDataLen);
    SAR_NOTSUPPORTYETERR
}

#[no_mangle]
pub extern "C" fn SKF_RSASignData(
    hContainer: *mut c_void,
    pbData: *const u8,
    ulDataLen: u32,
    pbSignature: *mut u8,
    pulSignLen: *mut u32,
) -> u32 {
    let _ = (hContainer, pbData, ulDataLen, pbSignature, pulSignLen);
    SAR_NOTSUPPORTYETERR
}

#[no_mangle]
pub extern "C" fn SKF_RSAVerify(
    hDev: *mut c_void,
    pRSAPubKeyBlob: *const c_void,
    pbData: *const u8,
    ulDataLen: u32,
    pbSignature: *const u8,
    ulSignLen: u32,
) -> u32 {
    let _ = (hDev, pRSAPubKeyBlob, pbData, ulDataLen, pbSignature, ulSignLen);
    SAR_NOTSUPPORTYETERR
}

#[no_mangle]
pub extern "C" fn SKF_RSAExportSessionKey(
    hContainer: *mut c_void,
    ulAlgID: u32,
    pPubKey: *const c_void,
    pbData: *mut u8,
    pulDataLen: *mut u32,
    phSessionKey: *mut *mut c_void,
) -> u32 {
    let _ = (hContainer, ulAlgID, pPubKey, pbData, pulDataLen, phSessionKey);
    SAR_NOTSUPPORTYETERR
}

#[no_mangle]
pub extern "C" fn SKF_ExtRSAPubKeyOperation(
    hDev: *mut c_void,
    pRSAPubKeyBlob: *const c_void,
    pbInput: *const u8,
    ulInputLen: u32,
    pbOutput: *mut u8,
    pulOutputLen: *mut u32,
) -> u32 {
    let _ = (hDev, pRSAPubKeyBlob, pbInput, ulInputLen, pbOutput, pulOutputLen);
    SAR_NOTSUPPORTYETERR
}

#[no_mangle]
pub extern "C" fn SKF_ExtRSAPriKeyOperation(
    hDev: *mut c_void,
    pRSAPriKeyBlob: *const c_void,
    pbInput: *const u8,
    ulInputLen: u32,
    pbOutput: *mut u8,
    pulOutputLen: *mut u32,
) -> u32 {
    let _ = (hDev, pRSAPriKeyBlob, pbInput, ulInputLen, pbOutput, pulOutputLen);
    SAR_NOTSUPPORTYETERR
}

// ──────── ECC 密钥协商 ────────

#[no_mangle]
pub extern "C" fn SKF_GenerateAgreementDataWithECC(
    hContainer: *mut c_void,
    ulAlgID: u32,
    pTempECCPubKey: *mut c_void,
    pbID: *const u8,
    ulIDLen: u32,
    phAgreementHandle: *mut *mut c_void,
) -> u32 {
    let _ = (hContainer, ulAlgID, pTempECCPubKey, pbID, ulIDLen, phAgreementHandle);
    SAR_NOTSUPPORTYETERR
}

#[no_mangle]
pub extern "C" fn SKF_GenerateAgreementDataAndKeyWithECC(
    hContainer: *mut c_void,
    ulAlgID: u32,
    pTempECCPubKey: *mut c_void,
    pTempECCPriKeyBlob: *const c_void,
    pECCPubKey: *const c_void,
    pbID: *const u8,
    ulIDLen: u32,
    pbRemoteID: *const u8,
    ulRemoteIDLen: u32,
    phKey: *mut *mut c_void,
) -> u32 {
    let _ = (hContainer, ulAlgID, pTempECCPubKey, pTempECCPriKeyBlob, pECCPubKey,
             pbID, ulIDLen, pbRemoteID, ulRemoteIDLen, phKey);
    SAR_NOTSUPPORTYETERR
}

#[no_mangle]
pub extern "C" fn SKF_GenerateKeyWithECC(
    phAgreementHandle: *mut c_void,
    pECCPubKey: *const c_void,
    pTempECCPubKey: *const c_void,
    pbRemoteID: *const u8,
    ulRemoteIDLen: u32,
    phKey: *mut *mut c_void,
) -> u32 {
    let _ = (phAgreementHandle, pECCPubKey, pTempECCPubKey, pbRemoteID, ulRemoteIDLen, phKey);
    SAR_NOTSUPPORTYETERR
}
