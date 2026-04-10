// SM3 哈希操作（支持单次和累积模式）
use libsmx::sm3;

/// 单次 SM3 哈希
pub fn sm3_digest(data: &[u8]) -> [u8; 32] {
    sm3::Sm3Hasher::digest(data)
}

/// 计算 SM2 Z 值：SM3(entlen||uid||curve_params||pubkey)
/// Reason: SM2 签名/验签标准流程需要先计算 Z 值与原文拼接后再哈希
pub fn sm2_z_value(pub_key_65: &[u8; 65], user_id: &[u8]) -> [u8; 32] {
    use libsmx::sm2;
    sm2::get_z(user_id, pub_key_65)
}

/// 计算 SM2 签名哈希：SM3(Z || message)
pub fn sm2_hash_with_z(pub_key_65: &[u8; 65], user_id: &[u8], message: &[u8]) -> [u8; 32] {
    use libsmx::sm2;
    let z = sm2::get_z(user_id, pub_key_65);
    sm2::get_e(&z, message)
}

/// SM3 哈希状态（用于 DigestInit/Update/Final 流程）
/// Reason: libsmx Sm3Hasher 仅支持单次调用，此处用 Vec 缓冲数据，DigestFinal 时一次性计算
#[derive(Debug, Clone, Default)]
pub struct Sm3State {
    pub buffer: Vec<u8>,
}

impl Sm3State {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    pub fn finalize(&self) -> [u8; 32] {
        sm3_digest(&self.buffer)
    }
}
