// GM/T 0016-2012 标准数据结构定义
// 所有结构体使用 #[repr(C)] 确保与 C 语言内存布局一致

/// 版本号结构
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VERSION {
    pub major: u8,
    pub minor: u8,
}

/// 设备信息结构（GM/T 0016 §5.2）
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DEVINFO {
    pub Version: VERSION,           // 版本
    pub Manufacturer: [u8; 64],     // 厂商信息（UTF-8）
    pub Issuer: [u8; 64],           // 发行者信息
    pub Label: [u8; 32],            // 设备标签
    pub SerialNumber: [u8; 32],     // 序列号
    pub HWVersion: VERSION,         // 硬件版本
    pub FirmwareVersion: VERSION,   // 固件版本
    pub AlgSymCap: u32,             // 对称算法能力位图
    pub AlgAsymCap: u32,            // 非对称算法能力位图
    pub AlgHashCap: u32,            // 哈希算法能力位图
    pub DevAuthAlgId: u32,          // 设备认证算法标识
    pub TotalSpace: u32,            // 总空间（字节）
    pub FreeSpace: u32,             // 可用空间（字节）
    pub MaxECCBufferSize: u32,      // 最大 ECC 缓冲区大小
    pub MaxBufferSize: u32,         // 最大通用缓冲区大小
    pub Reserved: [u8; 64],         // 保留
}

impl Default for DEVINFO {
    fn default() -> Self {
        Self {
            Version: VERSION { major: 1, minor: 0 },
            Manufacturer: [0u8; 64],
            Issuer: [0u8; 64],
            Label: [0u8; 32],
            SerialNumber: [0u8; 32],
            HWVersion: VERSION { major: 1, minor: 0 },
            FirmwareVersion: VERSION { major: 1, minor: 0 },
            AlgSymCap: 0x00000402,   // SM4-CBC
            AlgAsymCap: 0x00020200,  // SM2
            AlgHashCap: 0x00000001,  // SM3
            DevAuthAlgId: 0x00020200,
            TotalSpace: 64 * 1024,
            FreeSpace: 60 * 1024,
            MaxECCBufferSize: 512,
            MaxBufferSize: 4096,
            Reserved: [0u8; 64],
        }
    }
}

/// ECC 公钥 Blob（GM/T 0016 §5.3.3）
/// BitLen=256 for SM2；XCoordinate/YCoordinate 各 64 字节，右对齐大端补零
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ECCPUBLICKEYBLOB {
    pub BitLen: u32,
    pub XCoordinate: [u8; 64], // 右对齐大端，高 32 字节补零
    pub YCoordinate: [u8; 64], // 右对齐大端，高 32 字节补零
}

impl Default for ECCPUBLICKEYBLOB {
    fn default() -> Self {
        Self { BitLen: 256, XCoordinate: [0u8; 64], YCoordinate: [0u8; 64] }
    }
}

/// ECC 私钥 Blob
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ECCPRIVATEKEYBLOB {
    pub BitLen: u32,
    pub PrivateKey: [u8; 64], // 右对齐大端，高 32 字节补零
}

impl Default for ECCPRIVATEKEYBLOB {
    fn default() -> Self {
        Self { BitLen: 256, PrivateKey: [0u8; 64] }
    }
}

/// ECC 签名 Blob（GM/T 0016 §5.3.4）
/// r 和 s 各 64 字节，右对齐大端补零
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ECCSIGNATUREBLOB {
    pub r: [u8; 64],
    pub s: [u8; 64],
}

impl Default for ECCSIGNATUREBLOB {
    fn default() -> Self {
        Self { r: [0u8; 64], s: [0u8; 64] }
    }
}

/// ECC 密文 Blob（GM/T 0016 §5.3.5）
/// C1(x,y) + C3(HASH) + CipherLen + Cipher(C2)
/// Reason: Cipher 字段在 C 规范中为变长（Cipher[1]），此处定义为固定最大长度供 Mock 使用
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ECCCIPHERBLOB {
    pub XCoordinate: [u8; 64], // C1.x，右对齐大端
    pub YCoordinate: [u8; 64], // C1.y，右对齐大端
    pub HASH: [u8; 32],        // C3 = SM3 哈希
    pub CipherLen: u32,        // C2 长度（字节）
    pub Cipher: [u8; 512],     // C2 密文数据（Mock 固定最大 512 字节）
}

impl Default for ECCCIPHERBLOB {
    fn default() -> Self {
        Self {
            XCoordinate: [0u8; 64],
            YCoordinate: [0u8; 64],
            HASH: [0u8; 32],
            CipherLen: 0,
            Cipher: [0u8; 512],
        }
    }
}

/// 数字信封 Blob（GM/T 0016 §5.3.6）
/// 用于 SKF_ImportECCKeyPair：SM2 加密的 SM4 密钥 + ECC 公钥信息
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ENVELOPEDKEYBLOB {
    pub Version: u32,
    pub ulSymmAlgID: u32,             // 对称算法 ID（SGD_SM4_CBC 等）
    pub ulBits: u32,                  // 密钥位长（128 for SM4）
    pub cbEncryptedPriKey: [u8; 64],  // SM2 加密后的私钥（可选，本 Mock 不使用）
    pub PubKey: ECCPUBLICKEYBLOB,     // 对应的 ECC 公钥
    pub ECCCipherBlob: ECCCIPHERBLOB, // SM2 加密的对称密钥
}

/// 对称加密参数（GM/T 0016 §5.3.7）
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct BLOCKCIPHERPARAM {
    pub IV: [u8; 32],      // 初始向量（CBC 模式使用前 IVLen 字节）
    pub IVLen: u32,        // IV 长度（SM4 = 16）
    pub PaddingType: u32,  // 填充类型：0=不填充，1=PKCS7
    pub FeedBitLen: u32,   // 反馈位长（流模式使用，CBC 忽略）
}

/// 文件属性结构（GM/T 0016 §5.3.8）
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FILEATTRIBUTE {
    pub FileName: [u8; 32],  // 文件名（UTF-8，最长 32 字节）
    pub FileSize: u32,       // 文件大小（字节）
    pub ReadRights: u32,     // 读权限
    pub WriteRights: u32,    // 写权限
}
