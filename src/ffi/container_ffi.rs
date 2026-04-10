// 容器 + 文件管理 FFI 导出
use std::os::raw::{c_void, c_char, c_int};
use crate::types::{FILEATTRIBUTE, ECCPUBLICKEYBLOB, ECCCIPHERBLOB, ENVELOPEDKEYBLOB};
use crate::skf_impl::container::*;
use crate::skf_impl::ecc::*;

// ──── 容器管理 ────

#[no_mangle]
pub extern "C" fn SKF_CreateContainer(
    h_application: *mut c_void,
    sz_container_name: *const c_char,
    ph_container: *mut *mut c_void,
) -> u32 {
    skf_create_container(h_application, sz_container_name as *const i8, ph_container)
}

#[no_mangle]
pub extern "C" fn SKF_DeleteContainer(h_application: *mut c_void, sz_container_name: *const c_char) -> u32 {
    skf_delete_container(h_application, sz_container_name as *const i8)
}

#[no_mangle]
pub extern "C" fn SKF_EnumContainer(
    h_application: *mut c_void,
    sz_container_name: *mut c_char,
    pul_size: *mut u32,
) -> u32 {
    skf_enum_container(h_application, sz_container_name as *mut i8, pul_size)
}

#[no_mangle]
pub extern "C" fn SKF_OpenContainer(
    h_application: *mut c_void,
    sz_container_name: *const c_char,
    ph_container: *mut *mut c_void,
) -> u32 {
    skf_open_container(h_application, sz_container_name as *const i8, ph_container)
}

#[no_mangle]
pub extern "C" fn SKF_CloseContainer(h_container: *mut c_void) -> u32 {
    skf_close_container(h_container)
}

#[no_mangle]
pub extern "C" fn SKF_GetContainerType(h_container: *mut c_void, pul_container_type: *mut u32) -> u32 {
    skf_get_container_type(h_container, pul_container_type)
}

// ──── 文件管理 ────

#[no_mangle]
pub extern "C" fn SKF_CreateFile(
    h_application: *mut c_void,
    sz_file_name: *const c_char,
    ul_file_size: u32,
    ul_read_rights: u32,
    ul_write_rights: u32,
) -> u32 {
    skf_create_file(h_application, sz_file_name as *const i8, ul_file_size, ul_read_rights, ul_write_rights)
}

#[no_mangle]
pub extern "C" fn SKF_DeleteFile(h_application: *mut c_void, sz_file_name: *const c_char) -> u32 {
    skf_delete_file(h_application, sz_file_name as *const i8)
}

#[no_mangle]
pub extern "C" fn SKF_EnumFiles(
    h_application: *mut c_void,
    sz_file_list: *mut c_char,
    pul_size: *mut u32,
) -> u32 {
    skf_enum_files(h_application, sz_file_list as *mut i8, pul_size)
}

#[no_mangle]
pub extern "C" fn SKF_GetFileInfo(
    h_application: *mut c_void,
    sz_file_name: *const c_char,
    p_file_info: *mut FILEATTRIBUTE,
) -> u32 {
    skf_get_file_info(h_application, sz_file_name as *const i8, p_file_info)
}

#[no_mangle]
pub extern "C" fn SKF_ReadFile(
    h_application: *mut c_void,
    sz_file_name: *const c_char,
    ul_offset: u32,
    ul_size: u32,
    pb_out: *mut u8,
    pul_out_len: *mut u32,
) -> u32 {
    skf_read_file(h_application, sz_file_name as *const i8, ul_offset, ul_size, pb_out, pul_out_len)
}

#[no_mangle]
pub extern "C" fn SKF_WriteFile(
    h_application: *mut c_void,
    sz_file_name: *const c_char,
    ul_offset: u32,
    pb_data: *const u8,
    ul_size: u32,
) -> u32 {
    skf_write_file(h_application, sz_file_name as *const i8, ul_offset, pb_data, ul_size)
}

// ──── 证书 + 公钥 ────

#[no_mangle]
pub extern "C" fn SKF_ImportCertificate(
    h_container: *mut c_void,
    b_sign_flag: c_int,
    pb_cert: *const u8,
    ul_cert_len: u32,
) -> u32 {
    skf_import_certificate(h_container, b_sign_flag, pb_cert, ul_cert_len)
}

#[no_mangle]
pub extern "C" fn SKF_ExportCertificate(
    h_container: *mut c_void,
    b_sign_flag: c_int,
    pb_cert: *mut u8,
    pul_cert_len: *mut u32,
) -> u32 {
    skf_export_certificate(h_container, b_sign_flag, pb_cert, pul_cert_len)
}

#[no_mangle]
pub extern "C" fn SKF_ExportPublicKey(
    h_container: *mut c_void,
    b_sign_flag: c_int,
    pb_blob: *mut u8,
    pul_blob_len: *mut u32,
) -> u32 {
    skf_export_public_key(h_container, b_sign_flag, pb_blob, pul_blob_len)
}

// ──── ECC 密钥管理 ────

#[no_mangle]
pub extern "C" fn SKF_GenECCKeyPair(
    h_container: *mut c_void,
    ul_alg_id: u32,
    p_blob: *mut ECCPUBLICKEYBLOB,
) -> u32 {
    skf_gen_ecc_keypair(h_container, ul_alg_id, p_blob)
}

#[no_mangle]
pub extern "C" fn SKF_ImportECCKeyPair(
    h_container: *mut c_void,
    p_enveloped_key_blob: *mut ENVELOPEDKEYBLOB,
) -> u32 {
    skf_import_ecc_keypair(h_container, p_enveloped_key_blob)
}

#[no_mangle]
pub extern "C" fn SKF_ECCSignData(
    h_container: *mut c_void,
    pb_data: *const u8,
    ul_data_len: u32,
    p_signature: *mut crate::types::ECCSIGNATUREBLOB,
) -> u32 {
    skf_ecc_sign_data(h_container, pb_data, ul_data_len, p_signature)
}

#[no_mangle]
pub extern "C" fn SKF_ECCVerify(
    h_dev: *mut c_void,
    p_pub_key: *const ECCPUBLICKEYBLOB,
    pb_data: *const u8,
    ul_data_len: u32,
    p_signature: *const crate::types::ECCSIGNATUREBLOB,
) -> u32 {
    skf_ecc_verify(h_dev, p_pub_key, pb_data, ul_data_len, p_signature)
}

#[no_mangle]
pub extern "C" fn SKF_ECCExportSessionKey(
    h_container: *mut c_void,
    ul_alg_id: u32,
    p_pub_key: *const ECCPUBLICKEYBLOB,
    p_cipher_blob: *mut ECCCIPHERBLOB,
    ph_session_key: *mut *mut c_void,
) -> u32 {
    skf_ecc_export_session_key(h_container, ul_alg_id, p_pub_key, p_cipher_blob, ph_session_key)
}

#[no_mangle]
pub extern "C" fn SKF_ImportSessionKey(
    h_container: *mut c_void,
    ul_alg_id: u32,
    pb_wrapped: *const u8,
    ul_wrapped_len: u32,
    ph_key: *mut *mut c_void,
) -> u32 {
    skf_import_session_key(h_container, ul_alg_id, pb_wrapped, ul_wrapped_len, ph_key)
}

#[no_mangle]
pub extern "C" fn SKF_ExtECCEncrypt(
    h_dev: *mut c_void,
    p_pub_key: *const ECCPUBLICKEYBLOB,
    pb_plain: *const u8,
    ul_plain_len: u32,
    p_cipher: *mut ECCCIPHERBLOB,
) -> u32 {
    skf_ext_ecc_encrypt(h_dev, p_pub_key, pb_plain, ul_plain_len, p_cipher)
}

#[no_mangle]
pub extern "C" fn SKF_ExtECCDecrypt(
    h_dev: *mut c_void,
    p_pri_key: *const crate::types::ECCPRIVATEKEYBLOB,
    p_cipher: *const ECCCIPHERBLOB,
    pb_plain: *mut u8,
    pul_plain_len: *mut u32,
) -> u32 {
    skf_ext_ecc_decrypt(h_dev, p_pri_key, p_cipher, pb_plain, pul_plain_len)
}

#[no_mangle]
pub extern "C" fn SKF_ExtECCSign(
    h_dev: *mut c_void,
    p_pri_key: *const crate::types::ECCPRIVATEKEYBLOB,
    pb_data: *const u8,
    ul_data_len: u32,
    p_signature: *mut crate::types::ECCSIGNATUREBLOB,
) -> u32 {
    skf_ext_ecc_sign(h_dev, p_pri_key, pb_data, ul_data_len, p_signature)
}

#[no_mangle]
pub extern "C" fn SKF_ExtECCVerify(
    h_dev: *mut c_void,
    p_pub_key: *const ECCPUBLICKEYBLOB,
    pb_data: *const u8,
    ul_data_len: u32,
    p_signature: *const crate::types::ECCSIGNATUREBLOB,
) -> u32 {
    skf_ext_ecc_verify(h_dev, p_pub_key, pb_data, ul_data_len, p_signature)
}
