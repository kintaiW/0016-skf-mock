// 0016-skf-mock 集成测试
// 覆盖完整调用链：设备连接 → 应用管理 → 容器管理 → 密码操作

use skf_mock::error_code::*;
use skf_mock::ffi::device_ffi::*;
use skf_mock::ffi::app_ffi::*;
use skf_mock::ffi::container_ffi::*;
use skf_mock::ffi::crypto_ffi::*;
use skf_mock::types::*;

use std::os::raw::c_void;
use std::ptr;

// ──────────────────────────────────────────────
// 辅助：连接设备，返回 DEVHANDLE
// ──────────────────────────────────────────────
fn connect_dev() -> *mut c_void {
    let dev_name = b"MockSKFDevice\0";
    let mut h_dev: *mut c_void = ptr::null_mut();
    let rc = unsafe {
        SKF_ConnectDev(dev_name.as_ptr() as *const i8, &mut h_dev)
    };
    assert_eq!(rc, SAR_OK, "SKF_ConnectDev 失败: 0x{:08X}", rc);
    assert!(!h_dev.is_null());
    h_dev
}

// ──────────────────────────────────────────────
// 1. 设备层测试
// ──────────────────────────────────────────────

#[test]
fn test_enum_dev() {
    // 查询缓冲区大小
    let mut size: u32 = 0;
    let rc = unsafe { SKF_EnumDev(0, ptr::null_mut(), &mut size) };
    assert_eq!(rc, SAR_OK, "SKF_EnumDev size query: 0x{:08X}", rc);
    assert!(size > 0, "设备名列表长度应 > 0");

    // 读取设备名
    let mut buf = vec![0i8; size as usize];
    let rc = unsafe { SKF_EnumDev(0, buf.as_mut_ptr(), &mut size) };
    assert_eq!(rc, SAR_OK, "SKF_EnumDev fill: 0x{:08X}", rc);
}

#[test]
fn test_connect_disconnect() {
    let h_dev = connect_dev();
    let rc = unsafe { SKF_DisConnectDev(h_dev) };
    assert_eq!(rc, SAR_OK, "SKF_DisConnectDev: 0x{:08X}", rc);
}

#[test]
fn test_get_dev_info() {
    let h_dev = connect_dev();
    let mut info = DEVINFO::default();
    let rc = unsafe { SKF_GetDevInfo(h_dev, &mut info) };
    assert_eq!(rc, SAR_OK, "SKF_GetDevInfo: 0x{:08X}", rc);
    assert_eq!(info.Version.major, 1);
    let _ = unsafe { SKF_DisConnectDev(h_dev) };
}

#[test]
fn test_gen_random() {
    let h_dev = connect_dev();
    let mut buf = [0u8; 16];
    let rc = unsafe { SKF_GenRandom(h_dev, buf.as_mut_ptr(), 16) };
    assert_eq!(rc, SAR_OK, "SKF_GenRandom: 0x{:08X}", rc);
    // 16 字节随机数不应全零（概率极低）
    assert_ne!(buf, [0u8; 16], "随机数不应全零");
    let _ = unsafe { SKF_DisConnectDev(h_dev) };
}

// ──────────────────────────────────────────────
// 2. 应用与 PIN 测试
// ──────────────────────────────────────────────

#[test]
fn test_app_lifecycle() {
    let h_dev = connect_dev();

    // 创建应用
    let app_name = b"TestApp\0";
    let admin_pin = b"11111111\0";
    let user_pin = b"22222222\0";
    let mut h_app: *mut c_void = ptr::null_mut();

    let rc = unsafe {
        SKF_CreateApplication(
            h_dev,
            app_name.as_ptr() as *const i8,
            admin_pin.as_ptr() as *const i8,
            6, // admin max retry
            user_pin.as_ptr() as *const i8,
            6, // user max retry
            0x0000FFFF, // rights
            &mut h_app,
        )
    };
    assert_eq!(rc, SAR_OK, "SKF_CreateApplication: 0x{:08X}", rc);
    assert!(!h_app.is_null());

    // 枚举应用
    let mut list_size: u32 = 0;
    let rc = unsafe { SKF_EnumApplication(h_dev, ptr::null_mut(), &mut list_size) };
    assert_eq!(rc, SAR_OK, "SKF_EnumApplication size: 0x{:08X}", rc);
    assert!(list_size > 0);

    // 关闭应用句柄
    let rc = unsafe { SKF_CloseApplication(h_app) };
    assert_eq!(rc, SAR_OK, "SKF_CloseApplication: 0x{:08X}", rc);

    // 重新打开
    let mut h_app2: *mut c_void = ptr::null_mut();
    let rc = unsafe {
        SKF_OpenApplication(h_dev, app_name.as_ptr() as *const i8, &mut h_app2)
    };
    assert_eq!(rc, SAR_OK, "SKF_OpenApplication: 0x{:08X}", rc);

    // 验证用户 PIN
    let mut remain: u32 = 0;
    let rc = unsafe {
        SKF_VerifyPIN(h_app2, USER_TYPE, user_pin.as_ptr() as *const i8, &mut remain)
    };
    assert_eq!(rc, SAR_OK, "SKF_VerifyPIN user: 0x{:08X}", rc);

    // 错误 PIN
    let bad_pin = b"99999999\0";
    let rc = unsafe {
        SKF_VerifyPIN(h_app2, USER_TYPE, bad_pin.as_ptr() as *const i8, &mut remain)
    };
    assert_ne!(rc, SAR_OK, "错误 PIN 应返回非 SAR_OK");
    assert!(remain < 6, "剩余次数应递减");

    let _ = unsafe { SKF_CloseApplication(h_app2) };
    let _ = unsafe { SKF_DisConnectDev(h_dev) };
}

// ──────────────────────────────────────────────
// 3. 容器 + ECC 密钥对测试
// ──────────────────────────────────────────────

fn setup_app_container() -> (*mut c_void, *mut c_void, *mut c_void) {
    let h_dev = connect_dev();

    // 创建/打开应用
    let app_name = b"CryptoApp\0";
    let admin_pin = b"11111111\0";
    let user_pin = b"22222222\0";
    let mut h_app: *mut c_void = ptr::null_mut();
    let rc = unsafe {
        SKF_CreateApplication(
            h_dev, app_name.as_ptr() as *const i8,
            admin_pin.as_ptr() as *const i8, 6,
            user_pin.as_ptr() as *const i8, 6,
            0x0000FFFF, &mut h_app,
        )
    };
    // 已存在时忽略错误，重新打开
    if rc != SAR_OK {
        let rc2 = unsafe { SKF_OpenApplication(h_dev, app_name.as_ptr() as *const i8, &mut h_app) };
        assert_eq!(rc2, SAR_OK, "SKF_OpenApplication: 0x{:08X}", rc2);
    }

    // 创建容器
    let cnt_name = b"TestContainer\0";
    let mut h_cnt: *mut c_void = ptr::null_mut();
    let rc = unsafe {
        SKF_CreateContainer(h_app, cnt_name.as_ptr() as *const i8, &mut h_cnt)
    };
    if rc != SAR_OK {
        let rc2 = unsafe { SKF_OpenContainer(h_app, cnt_name.as_ptr() as *const i8, &mut h_cnt) };
        assert_eq!(rc2, SAR_OK, "SKF_OpenContainer: 0x{:08X}", rc2);
    }

    (h_dev, h_app, h_cnt)
}

#[test]
fn test_container_lifecycle() {
    let (h_dev, h_app, h_cnt) = setup_app_container();

    // 获取容器类型
    let mut ctype: u32 = 0;
    let rc = unsafe { SKF_GetContainerType(h_cnt, &mut ctype) };
    assert_eq!(rc, SAR_OK, "SKF_GetContainerType: 0x{:08X}", rc);

    let _ = unsafe { SKF_CloseContainer(h_cnt) };
    let _ = unsafe { SKF_CloseApplication(h_app) };
    let _ = unsafe { SKF_DisConnectDev(h_dev) };
}

// ──────────────────────────────────────────────
// 4. SM2 签名/验签端到端
// ──────────────────────────────────────────────

#[test]
fn test_sm2_sign_verify() {
    let (h_dev, h_app, h_cnt) = setup_app_container();

    // 生成签名密钥对
    let mut pub_key_blob = ECCPUBLICKEYBLOB::default();
    let rc = unsafe { SKF_GenECCKeyPair(h_cnt, SGD_SM2_1, &mut pub_key_blob) };
    assert_eq!(rc, SAR_OK, "SKF_GenECCKeyPair sign: 0x{:08X}", rc);
    assert_eq!(pub_key_blob.BitLen, 256);

    // 对消息签名
    let msg = b"hello skf sm2 sign";
    let mut sig_blob = ECCSIGNATUREBLOB::default();
    let rc = unsafe {
        SKF_ECCSignData(h_cnt, msg.as_ptr(), msg.len() as u32, &mut sig_blob)
    };
    assert_eq!(rc, SAR_OK, "SKF_ECCSignData: 0x{:08X}", rc);

    // 验签（使用设备句柄 + 公钥）
    let rc = unsafe {
        SKF_ECCVerify(h_dev, &pub_key_blob, msg.as_ptr(), msg.len() as u32, &sig_blob)
    };
    assert_eq!(rc, SAR_OK, "SKF_ECCVerify: 0x{:08X}", rc);

    // 篡改数据后验签应失败
    let bad_msg = b"tampered message!";
    let rc = unsafe {
        SKF_ECCVerify(h_dev, &pub_key_blob, bad_msg.as_ptr(), bad_msg.len() as u32, &sig_blob)
    };
    assert_ne!(rc, SAR_OK, "篡改后验签应失败");

    let _ = unsafe { SKF_CloseContainer(h_cnt) };
    let _ = unsafe { SKF_CloseApplication(h_app) };
    let _ = unsafe { SKF_DisConnectDev(h_dev) };
}

// ──────────────────────────────────────────────
// 5. SM2 外部公私钥加解密
// ──────────────────────────────────────────────

#[test]
fn test_sm2_ext_encrypt_decrypt() {
    let h_dev = connect_dev();

    // 生成测试密钥对（通过 skf_impl 层）
    let (priv_bytes, pub_key_65) = skf_mock::crypto::sm2_ops::sm2_generate_keypair();

    let pub_blob = skf_mock::crypto::sm2_ops::pub_key_to_blob(&pub_key_65);
    let mut pri_blob = ECCPRIVATEKEYBLOB::default();
    pri_blob.BitLen = 256;
    pri_blob.PrivateKey[32..].copy_from_slice(&priv_bytes);

    let plain = b"hello sm2 encryption";
    let mut cipher_blob = ECCCIPHERBLOB::default();

    // 加密
    let rc = unsafe {
        SKF_ExtECCEncrypt(h_dev, &pub_blob, plain.as_ptr(), plain.len() as u32, &mut cipher_blob)
    };
    assert_eq!(rc, SAR_OK, "SKF_ExtECCEncrypt: 0x{:08X}", rc);
    assert!(cipher_blob.CipherLen > 0);

    // 解密
    let mut out_buf = vec![0u8; 256];
    let mut out_len: u32 = 256;
    let rc = unsafe {
        SKF_ExtECCDecrypt(h_dev, &pri_blob, &cipher_blob, out_buf.as_mut_ptr(), &mut out_len)
    };
    assert_eq!(rc, SAR_OK, "SKF_ExtECCDecrypt: 0x{:08X}", rc);
    assert_eq!(&out_buf[..out_len as usize], plain as &[u8]);

    let _ = unsafe { SKF_DisConnectDev(h_dev) };
}

// ──────────────────────────────────────────────
// 6. SM2 外部公私钥签名/验签
// ──────────────────────────────────────────────

#[test]
fn test_sm2_ext_sign_verify() {
    let h_dev = connect_dev();

    let (priv_bytes, pub_key_65) = skf_mock::crypto::sm2_ops::sm2_generate_keypair();
    let pub_blob = skf_mock::crypto::sm2_ops::pub_key_to_blob(&pub_key_65);
    let mut pri_blob = ECCPRIVATEKEYBLOB::default();
    pri_blob.BitLen = 256;
    pri_blob.PrivateKey[32..].copy_from_slice(&priv_bytes);

    let msg = b"test ext sign";
    let mut sig_blob = ECCSIGNATUREBLOB::default();

    let rc = unsafe {
        SKF_ExtECCSign(h_dev, &pri_blob, msg.as_ptr(), msg.len() as u32, &mut sig_blob)
    };
    assert_eq!(rc, SAR_OK, "SKF_ExtECCSign: 0x{:08X}", rc);

    let rc = unsafe {
        SKF_ExtECCVerify(h_dev, &pub_blob, msg.as_ptr(), msg.len() as u32, &sig_blob)
    };
    assert_eq!(rc, SAR_OK, "SKF_ExtECCVerify: 0x{:08X}", rc);

    let _ = unsafe { SKF_DisConnectDev(h_dev) };
}

// ──────────────────────────────────────────────
// 7. 会话密钥导出/导入
// ──────────────────────────────────────────────

#[test]
fn test_session_key_export_import() {
    let (h_dev, h_app, h_cnt) = setup_app_container();

    // 生成接收方加密密钥对
    let mut recv_pub = ECCPUBLICKEYBLOB::default();
    let rc = unsafe { SKF_GenECCKeyPair(h_cnt, SGD_SM2_3, &mut recv_pub) };
    assert_eq!(rc, SAR_OK, "GenECCKeyPair enc: 0x{:08X}", rc);

    // 发送方导出会话密钥
    let mut cipher_blob = ECCCIPHERBLOB::default();
    let mut h_session_key: *mut c_void = ptr::null_mut();
    let rc = unsafe {
        SKF_ECCExportSessionKey(h_cnt, SGD_SM4_CBC, &recv_pub, &mut cipher_blob, &mut h_session_key)
    };
    assert_eq!(rc, SAR_OK, "SKF_ECCExportSessionKey: 0x{:08X}", rc);
    assert!(!h_session_key.is_null());

    // 接收方导入会话密钥（从 ECCCIPHERBLOB 转为字节序列）
    let cipher_bytes = skf_mock::crypto::sm2_ops::blob_to_cipher_bytes(&cipher_blob);
    let mut h_imported_key: *mut c_void = ptr::null_mut();
    let rc = unsafe {
        SKF_ImportSessionKey(
            h_cnt, SGD_SM4_CBC,
            cipher_bytes.as_ptr(), cipher_bytes.len() as u32,
            &mut h_imported_key,
        )
    };
    assert_eq!(rc, SAR_OK, "SKF_ImportSessionKey: 0x{:08X}", rc);

    // 清理
    let _ = unsafe { SKF_DestroyKey(h_session_key) };
    let _ = unsafe { SKF_DestroyKey(h_imported_key) };
    let _ = unsafe { SKF_CloseContainer(h_cnt) };
    let _ = unsafe { SKF_CloseApplication(h_app) };
    let _ = unsafe { SKF_DisConnectDev(h_dev) };
}

// ──────────────────────────────────────────────
// 8. SM4-CBC 加解密端到端
// ──────────────────────────────────────────────

#[test]
fn test_sm4_cbc_encrypt_decrypt() {
    let h_dev = connect_dev();

    // 设置对称密钥
    let key = [0x01u8; 16];
    let mut h_key: *mut c_void = ptr::null_mut();
    let rc = unsafe { SKF_SetSymmKey(h_dev, key.as_ptr(), SGD_SM4_CBC, &mut h_key) };
    assert_eq!(rc, SAR_OK, "SKF_SetSymmKey CBC: 0x{:08X}", rc);

    // 初始化加密（PaddingType=1 启用 PKCS7）
    let mut enc_param = BLOCKCIPHERPARAM::default();
    enc_param.IVLen = 16;
    enc_param.PaddingType = 1;
    let rc = unsafe { SKF_EncryptInit(h_key, enc_param) };
    assert_eq!(rc, SAR_OK, "SKF_EncryptInit: 0x{:08X}", rc);

    // 加密（PKCS7 padding = 1）
    let plain = b"hello skf sm4 cbc";
    let mut enc_buf = vec![0u8; 64];
    let mut enc_len: u32 = 64;
    let rc = unsafe {
        SKF_Encrypt(h_key, plain.as_ptr(), plain.len() as u32, enc_buf.as_mut_ptr(), &mut enc_len)
    };
    assert_eq!(rc, SAR_OK, "SKF_Encrypt: 0x{:08X}", rc);
    assert!(enc_len > 0 && enc_len % 16 == 0, "加密长度应为 16 的倍数");

    // 重置密钥用于解密
    let mut h_key2: *mut c_void = ptr::null_mut();
    let rc = unsafe { SKF_SetSymmKey(h_dev, key.as_ptr(), SGD_SM4_CBC, &mut h_key2) };
    assert_eq!(rc, SAR_OK);

    let mut dec_param = BLOCKCIPHERPARAM::default();
    dec_param.IVLen = 16;
    dec_param.PaddingType = 1;
    let rc = unsafe { SKF_DecryptInit(h_key2, dec_param) };
    assert_eq!(rc, SAR_OK, "SKF_DecryptInit: 0x{:08X}", rc);

    let mut dec_buf = vec![0u8; 64];
    let mut dec_len: u32 = 64;
    let rc = unsafe {
        SKF_Decrypt(h_key2, enc_buf.as_ptr(), enc_len, dec_buf.as_mut_ptr(), &mut dec_len)
    };
    assert_eq!(rc, SAR_OK, "SKF_Decrypt: 0x{:08X}", rc);
    assert_eq!(&dec_buf[..dec_len as usize], plain as &[u8]);

    let _ = unsafe { SKF_DestroyKey(h_key) };
    let _ = unsafe { SKF_DestroyKey(h_key2) };
    let _ = unsafe { SKF_DisConnectDev(h_dev) };
}

// ──────────────────────────────────────────────
// 9. SM4-ECB 加解密端到端
// ──────────────────────────────────────────────

#[test]
fn test_sm4_ecb_encrypt_decrypt() {
    let h_dev = connect_dev();

    let key = [0xAAu8; 16];
    let mut h_enc: *mut c_void = ptr::null_mut();
    let mut h_dec: *mut c_void = ptr::null_mut();
    unsafe { SKF_SetSymmKey(h_dev, key.as_ptr(), SGD_SM4_ECB, &mut h_enc) };
    unsafe { SKF_SetSymmKey(h_dev, key.as_ptr(), SGD_SM4_ECB, &mut h_dec) };

    let enc_param = BLOCKCIPHERPARAM::default();
    unsafe { SKF_EncryptInit(h_enc, enc_param) };
    let dec_param = BLOCKCIPHERPARAM::default();
    unsafe { SKF_DecryptInit(h_dec, dec_param) };

    let plain = b"ecb mode test 16"; // 恰好 16 字节，padding 后 32 字节
    let mut enc_buf = [0u8; 64];
    let mut enc_len: u32 = 64;
    let rc = unsafe {
        SKF_Encrypt(h_enc, plain.as_ptr(), plain.len() as u32, enc_buf.as_mut_ptr(), &mut enc_len)
    };
    assert_eq!(rc, SAR_OK, "ECB Encrypt: 0x{:08X}", rc);

    let mut dec_buf = [0u8; 64];
    let mut dec_len: u32 = 64;
    let rc = unsafe {
        SKF_Decrypt(h_dec, enc_buf.as_ptr(), enc_len, dec_buf.as_mut_ptr(), &mut dec_len)
    };
    assert_eq!(rc, SAR_OK, "ECB Decrypt: 0x{:08X}", rc);
    assert_eq!(&dec_buf[..dec_len as usize], plain as &[u8]);

    let _ = unsafe { SKF_DestroyKey(h_enc) };
    let _ = unsafe { SKF_DestroyKey(h_dec) };
    let _ = unsafe { SKF_DisConnectDev(h_dev) };
}

// ──────────────────────────────────────────────
// 10. SM3 哈希（DigestInit/Update/Final）
// ──────────────────────────────────────────────

#[test]
fn test_sm3_digest() {
    let h_dev = connect_dev();

    let mut h_hash: *mut c_void = ptr::null_mut();
    let rc = unsafe {
        SKF_DigestInit(h_dev, SGD_SM3, ptr::null(), ptr::null(), 0, &mut h_hash)
    };
    assert_eq!(rc, SAR_OK, "SKF_DigestInit: 0x{:08X}", rc);

    let data1 = b"hello ";
    let data2 = b"world";
    let rc = unsafe { SKF_DigestUpdate(h_hash, data1.as_ptr(), data1.len() as u32) };
    assert_eq!(rc, SAR_OK, "SKF_DigestUpdate 1: 0x{:08X}", rc);
    let rc = unsafe { SKF_DigestUpdate(h_hash, data2.as_ptr(), data2.len() as u32) };
    assert_eq!(rc, SAR_OK, "SKF_DigestUpdate 2: 0x{:08X}", rc);

    let mut digest = [0u8; 32];
    let mut digest_len: u32 = 32;
    let rc = unsafe { SKF_DigestFinal(h_hash, digest.as_mut_ptr(), &mut digest_len) };
    assert_eq!(rc, SAR_OK, "SKF_DigestFinal: 0x{:08X}", rc);
    assert_eq!(digest_len, 32);
    assert_ne!(digest, [0u8; 32], "摘要不应全零");

    // 与直接调用 sm3_digest("hello world") 对比
    let expected = skf_mock::crypto::sm3_ops::sm3_digest(b"hello world");
    assert_eq!(digest, expected, "分段 Update 结果应与一次性计算一致");

    let _ = unsafe { SKF_CloseHash(h_hash) };
    let _ = unsafe { SKF_DisConnectDev(h_dev) };
}

// ──────────────────────────────────────────────
// 11. SM3 单次 Digest（含 Z 值）
// ──────────────────────────────────────────────

#[test]
fn test_sm3_digest_with_z() {
    let h_dev = connect_dev();

    // 生成临时 SM2 密钥对用于 Z 值计算
    let (_, pub_key_65) = skf_mock::crypto::sm2_ops::sm2_generate_keypair();
    let pub_blob = skf_mock::crypto::sm2_ops::pub_key_to_blob(&pub_key_65);

    let uid = b"1234567812345678";
    let mut h_hash: *mut c_void = ptr::null_mut();
    let rc = unsafe {
        SKF_DigestInit(h_dev, SGD_SM3, &pub_blob, uid.as_ptr(), uid.len() as u32, &mut h_hash)
    };
    assert_eq!(rc, SAR_OK, "DigestInit with pubkey: 0x{:08X}", rc);

    let msg = b"test message for z-value hash";
    let mut digest = [0u8; 32];
    let mut digest_len: u32 = 32;
    let rc = unsafe {
        SKF_Digest(h_hash, msg.as_ptr(), msg.len() as u32, digest.as_mut_ptr(), &mut digest_len)
    };
    assert_eq!(rc, SAR_OK, "SKF_Digest: 0x{:08X}", rc);
    assert_eq!(digest_len, 32);
    assert_ne!(digest, [0u8; 32]);

    // 与直接计算 sm3(Z || msg) 对比
    let z = skf_mock::crypto::sm3_ops::sm2_z_value(&pub_key_65, uid);
    let mut combined = z.to_vec();
    combined.extend_from_slice(msg);
    let expected = skf_mock::crypto::sm3_ops::sm3_digest(&combined);
    assert_eq!(digest, expected, "Z 值哈希结果应与手动计算一致");

    let _ = unsafe { SKF_CloseHash(h_hash) };
    let _ = unsafe { SKF_DisConnectDev(h_dev) };
}

// ──────────────────────────────────────────────
// 12. 文件读写
// ──────────────────────────────────────────────

#[test]
fn test_file_read_write() {
    let (h_dev, h_app, h_cnt) = setup_app_container();

    // 在容器内写文件
    let file_name = b"TestFile\0";
    let content = b"file content data";

    // SKF 规范中文件挂在应用下，使用 h_app（不是 h_cnt）
    let rc = unsafe {
        SKF_CreateFile(h_app, file_name.as_ptr() as *const i8, 64, 0xFF, 0xFF)
    };
    if rc != SAR_OK {
        // 已存在则直接写
    }

    let rc = unsafe {
        SKF_WriteFile(h_app, file_name.as_ptr() as *const i8, 0, content.as_ptr(), content.len() as u32)
    };
    assert_eq!(rc, SAR_OK, "SKF_WriteFile: 0x{:08X}", rc);

    // 读文件
    let mut read_buf = [0u8; 64];
    let mut read_len: u32 = 64;
    let rc = unsafe {
        SKF_ReadFile(h_app, file_name.as_ptr() as *const i8, 0, read_len, read_buf.as_mut_ptr(), &mut read_len)
    };
    assert_eq!(rc, SAR_OK, "SKF_ReadFile: 0x{:08X}", rc);
    assert_eq!(&read_buf[..content.len()], content as &[u8]);

    let _ = unsafe { SKF_CloseContainer(h_cnt) };
    let _ = unsafe { SKF_CloseApplication(h_app) };
    let _ = unsafe { SKF_DisConnectDev(h_dev) };
}
