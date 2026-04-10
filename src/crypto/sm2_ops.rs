// SM2 密码操作 + 公钥格式转换
// libsmx 使用 65字节 04||x(32)||y(32)，SKF 使用 ECCPUBLICKEYBLOB { BitLen, X[64], Y[64] }（右对齐大端）

use crate::types::{ECCPUBLICKEYBLOB, ECCCIPHERBLOB, ECCSIGNATUREBLOB, ECCPRIVATEKEYBLOB};

/// 默认 SM2 用户 ID（16字节，符合 GM/T 标准默认值）
pub const DEFAULT_USER_ID: &[u8] = b"1234567812345678";

// ──────── 公钥格式转换 ────────

/// libsmx 65字节公钥 → ECCPUBLICKEYBLOB（SKF 格式，右对齐大端）
/// Reason: libsmx 使用紧凑的 04||x||y 格式，SKF 规范要求 64 字节右对齐
pub fn pub_key_to_blob(pk_65: &[u8; 65]) -> ECCPUBLICKEYBLOB {
    let mut blob = ECCPUBLICKEYBLOB::default();
    blob.BitLen = 256;
    // x 坐标在 pk_65[1..33]，右对齐写入 XCoordinate[32..64]
    blob.XCoordinate[32..].copy_from_slice(&pk_65[1..33]);
    // y 坐标在 pk_65[33..65]，右对齐写入 YCoordinate[32..64]
    blob.YCoordinate[32..].copy_from_slice(&pk_65[33..65]);
    blob
}

/// ECCPUBLICKEYBLOB → libsmx 65字节公钥
pub fn blob_to_pub_key(blob: &ECCPUBLICKEYBLOB) -> [u8; 65] {
    let mut pk = [0u8; 65];
    pk[0] = 0x04;
    pk[1..33].copy_from_slice(&blob.XCoordinate[32..]);
    pk[33..65].copy_from_slice(&blob.YCoordinate[32..]);
    pk
}

/// ECCPRIVATEKEYBLOB → libsmx 32字节私钥
pub fn pri_blob_to_key(blob: &ECCPRIVATEKEYBLOB) -> [u8; 32] {
    let mut k = [0u8; 32];
    k.copy_from_slice(&blob.PrivateKey[32..]);
    k
}

/// libsmx 32字节私钥 → ECCPRIVATEKEYBLOB
pub fn pri_key_to_blob(key: &[u8; 32]) -> ECCPRIVATEKEYBLOB {
    let mut blob = ECCPRIVATEKEYBLOB::default();
    blob.BitLen = 256;
    blob.PrivateKey[32..].copy_from_slice(key);
    blob
}

// ──────── 签名格式转换 ────────

/// libsmx 64字节 r(32)||s(32) → ECCSIGNATUREBLOB（各 64 字节右对齐）
pub fn sig_to_blob(sig_64: &[u8; 64]) -> ECCSIGNATUREBLOB {
    let mut blob = ECCSIGNATUREBLOB::default();
    blob.r[32..].copy_from_slice(&sig_64[..32]);
    blob.s[32..].copy_from_slice(&sig_64[32..]);
    blob
}

/// ECCSIGNATUREBLOB → libsmx 64字节 r||s
pub fn blob_to_sig(blob: &ECCSIGNATUREBLOB) -> [u8; 64] {
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&blob.r[32..]);
    sig[32..].copy_from_slice(&blob.s[32..]);
    sig
}

// ──────── 密文格式转换 ────────

/// libsmx 密文字节 → ECCCIPHERBLOB
/// libsmx 输出格式：04||C1.x(32)||C1.y(32)||C3(32)||C2(n)，共 97+n 字节
pub fn cipher_bytes_to_blob(cipher: &[u8]) -> Option<ECCCIPHERBLOB> {
    if cipher.len() < 97 || cipher[0] != 0x04 {
        return None;
    }
    let mut blob = ECCCIPHERBLOB::default();
    // C1.x → XCoordinate[32..64]（右对齐）
    blob.XCoordinate[32..].copy_from_slice(&cipher[1..33]);
    // C1.y → YCoordinate[32..64]
    blob.YCoordinate[32..].copy_from_slice(&cipher[33..65]);
    // C3 → HASH
    blob.HASH.copy_from_slice(&cipher[65..97]);
    // C2 → Cipher
    let c2 = &cipher[97..];
    if c2.len() > blob.Cipher.len() {
        return None; // 密文超出 Mock 支持的最大大小
    }
    blob.CipherLen = c2.len() as u32;
    blob.Cipher[..c2.len()].copy_from_slice(c2);
    Some(blob)
}

/// ECCCIPHERBLOB → libsmx 密文字节（04||C1.x||C1.y||C3||C2）
pub fn blob_to_cipher_bytes(blob: &ECCCIPHERBLOB) -> Vec<u8> {
    let c2_len = blob.CipherLen as usize;
    let mut out = Vec::with_capacity(97 + c2_len);
    out.push(0x04);
    out.extend_from_slice(&blob.XCoordinate[32..]); // 取低 32 字节（有效坐标）
    out.extend_from_slice(&blob.YCoordinate[32..]);
    out.extend_from_slice(&blob.HASH);
    out.extend_from_slice(&blob.Cipher[..c2_len]);
    out
}

// ──────── SM2 密码操作 ────────

/// SM2 签名（含 Z 值计算），返回 64 字节 r||s
pub fn sm2_sign(priv_key: &[u8; 32], data: &[u8]) -> Option<[u8; 64]> {
    use libsmx::sm2;
    use rand::rngs::OsRng;
    let pk = sm2::PrivateKey::from_bytes(priv_key).ok()?;
    let sig = sm2::sign_message(data, DEFAULT_USER_ID, &pk, &mut OsRng);
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&sig);
    Some(arr)
}

/// SM2 验签（含 Z 值计算）
pub fn sm2_verify(pub_key: &[u8; 65], data: &[u8], sig: &[u8; 64]) -> bool {
    use libsmx::sm2;
    sm2::verify_message(data, DEFAULT_USER_ID, pub_key, sig).is_ok()
}

/// SM2 加密（SM2 非对称加密，输出 libsmx 格式密文字节）
pub fn sm2_encrypt(pub_key: &[u8; 65], plaintext: &[u8]) -> Option<Vec<u8>> {
    use libsmx::sm2;
    use rand::rngs::OsRng;
    sm2::encrypt(pub_key, plaintext, &mut OsRng).ok()
}

/// SM2 解密
pub fn sm2_decrypt(priv_key: &[u8; 32], ciphertext: &[u8]) -> Option<Vec<u8>> {
    use libsmx::sm2;
    let pk = sm2::PrivateKey::from_bytes(priv_key).ok()?;
    sm2::decrypt(&pk, ciphertext).ok()
}

/// SM2 生成密钥对，返回 (私钥 32字节, 公钥 65字节)
pub fn sm2_generate_keypair() -> ([u8; 32], [u8; 65]) {
    use libsmx::sm2;
    use rand::rngs::OsRng;
    let (priv_key, pub_key) = sm2::generate_keypair(&mut OsRng);
    let mut priv_bytes = [0u8; 32];
    priv_bytes.copy_from_slice(priv_key.as_bytes());
    (priv_bytes, pub_key)
}
