// SM4 加解密操作（支持 ECB 和 CBC 模式）
use libsmx::sm4;

/// SM4-CBC 加密（含手工 PKCS7 padding）
/// Reason: libsmx sm4_encrypt_cbc 不含 PKCS7 padding，需手工处理
pub fn sm4_cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8], padding: bool) -> Vec<u8> {
    let padded = if padding {
        pkcs7_pad(data, 16)
    } else {
        data.to_vec()
    };
    sm4::sm4_encrypt_cbc(key, iv, &padded)
}

/// SM4-CBC 解密（含手工 PKCS7 unpadding）
pub fn sm4_cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8], padding: bool) -> Option<Vec<u8>> {
    let plain = sm4::sm4_decrypt_cbc(key, iv, data);
    if padding {
        pkcs7_unpad(&plain).ok()
    } else {
        Some(plain)
    }
}

/// SM4-ECB 加密
pub fn sm4_ecb_encrypt(key: &[u8; 16], data: &[u8], padding: bool) -> Vec<u8> {
    let padded = if padding { pkcs7_pad(data, 16) } else { data.to_vec() };
    sm4::sm4_encrypt_ecb(key, &padded)
}

/// SM4-ECB 解密
pub fn sm4_ecb_decrypt(key: &[u8; 16], data: &[u8], padding: bool) -> Option<Vec<u8>> {
    let plain = sm4::sm4_decrypt_ecb(key, data);
    if padding { pkcs7_unpad(&plain).ok() } else { Some(plain) }
}

// ──────── PKCS7 填充 ────────

fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let pad_len = block_size - (data.len() % block_size);
    let mut padded = data.to_vec();
    padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));
    padded
}

fn pkcs7_unpad(data: &[u8]) -> Result<Vec<u8>, ()> {
    let pad_len = *data.last().ok_or(())? as usize;
    if pad_len == 0 || pad_len > 16 || pad_len > data.len() {
        return Err(());
    }
    Ok(data[..data.len() - pad_len].to_vec())
}
