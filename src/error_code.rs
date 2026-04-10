// GM/T 0016-2012 标准错误码定义
// 参考：GM/T 0016 §6 错误代码

/// 操作成功
pub const SAR_OK: u32 = 0x00000000;
/// 失败
pub const SAR_FAIL: u32 = 0x0A000001;
/// 未知错误
pub const SAR_UNKNOWNERR: u32 = 0x0A000002;
/// 不支持的接口调用
pub const SAR_NOTSUPPORTYETERR: u32 = 0x0A000003;
/// 文件操作错误
pub const SAR_FILEERR: u32 = 0x0A000004;
/// 无效句柄
pub const SAR_INVALIDHANDLEERR: u32 = 0x0A000005;
/// 无效参数（指针为空、长度非法等）
pub const SAR_INVALIDPARAMERR: u32 = 0x0A000006;
/// 读文件错误
pub const SAR_READFILEERR: u32 = 0x0A000007;
/// 写文件错误
pub const SAR_WRITEFILEERR: u32 = 0x0A000008;
/// 名称长度错误
pub const SAR_NAMELENERR: u32 = 0x0A000009;
/// 密钥用途错误
pub const SAR_KEYUSAGEERR: u32 = 0x0A00000A;
/// 模长错误
pub const SAR_MODULUSLENERR: u32 = 0x0A00000B;
/// 未初始化
pub const SAR_NOTINITIALIZEERR: u32 = 0x0A00000C;
/// 对象错误
pub const SAR_OBJERR: u32 = 0x0A00000D;
/// 内存错误
pub const SAR_MEMORYERR: u32 = 0x0A00000E;
/// 超时
pub const SAR_TIMEOUTERR: u32 = 0x0A00000F;
/// 输入数据错误
pub const SAR_INDATAERR: u32 = 0x0A000010;
/// 输入数据长度错误
pub const SAR_INDATALENERR: u32 = 0x0A000011;
/// 输出数据错误
pub const SAR_OUTDATAERR: u32 = 0x0A000012;
/// 输出数据长度错误
pub const SAR_OUTDATALENERR: u32 = 0x0A000013;
/// 哈希对象初始化错误
pub const SAR_HASHOBJINITERR: u32 = 0x0A000014;
/// 哈希参数错误
pub const SAR_HASHPARAMERR: u32 = 0x0A000015;
/// 哈希未初始化
pub const SAR_HASHNOTINITIALIZEERR: u32 = 0x0A000016;
/// 哈希内部错误
pub const SAR_HASHINTERR: u32 = 0x0A000017;
/// 生成终止错误
pub const SAR_GENABORTERR: u32 = 0x0A000018;
/// 密钥未初始化
pub const SAR_KEYNOTINITIALIZEERR: u32 = 0x0A000019;
/// 证书不匹配
pub const SAR_CERTDNOTMATCHERR: u32 = 0x0A00001A;
/// 密钥未找到
pub const SAR_KEYNOTFOUNDERR: u32 = 0x0A00001B;
/// 证书未找到
pub const SAR_CERTNOTFOUNDERR: u32 = 0x0A00001C;
/// 无法导出
pub const SAR_NOTEXPORTERR: u32 = 0x0A00001D;
/// 解密加载失败
pub const SAR_DECLOADERR: u32 = 0x0A00001E;
/// 应用不存在
pub const SAR_APPLICATION_NOT_EXISTS: u32 = 0x0A000020;
/// 应用已存在
pub const SAR_APPLICATION_EXISTS: u32 = 0x0A000021;
/// 用户已登录
pub const SAR_USER_ALREADY_LOGGED_IN: u32 = 0x0A000022;
/// 用户 PIN 未初始化
pub const SAR_USER_PIN_NOT_INITIALIZED: u32 = 0x0A000023;
/// 用户类型无效
pub const SAR_USER_TYPE_INVALID: u32 = 0x0A000024;
/// 认证码错误（PIN 错误）
pub const SAR_AUTHCODEERR: u32 = 0x0A000025;
/// 认证码太长
pub const SAR_AUTHCODETOOLONGERR: u32 = 0x0A000026;
/// 容器不存在
pub const SAR_CONTAINER_NOT_EXISTS: u32 = 0x0A000027;
/// 容器已存在
pub const SAR_CONTAINER_EXISTS: u32 = 0x0A000028;
/// PIN 不正确
pub const SAR_PIN_INCORRECT: u32 = 0x0A000029;
/// PIN 已锁定
pub const SAR_PIN_LOCKED: u32 = 0x0A00002A;

// PIN 类型常量
pub const ADMIN_TYPE: u32 = 0; // 管理员 PIN
pub const USER_TYPE: u32 = 1;  // 用户 PIN

// 容器类型
pub const CONTAINER_TYPE_EMPTY: u32 = 0;
pub const CONTAINER_TYPE_RSA: u32 = 1;
pub const CONTAINER_TYPE_ECC: u32 = 2;

// 算法 ID（GM/T 0016 SKF 标准定义，与 GM/T 0018 SDF 不同）
// Reason: GM/T 0016 SKF 规范使用独立的算法 ID 体系；mPlugin JS 端常量以此为准
pub const SGD_SM2_1: u32 = 0x00020100; // SM2 椭圆曲线签名算法
pub const SGD_SM2_2: u32 = 0x00020200; // SM2 椭圆曲线密钥交换协议
pub const SGD_SM2_3: u32 = 0x00020400; // SM2 椭圆曲线加密算法
pub const SGD_SM3: u32 = 0x00000001;   // SM3 哈希算法
pub const SGD_SM4_ECB: u32 = 0x00000401; // SM4 ECB
pub const SGD_SM4_CBC: u32 = 0x00000402; // SM4 CBC

// 设备状态
pub const DEV_PRESENT: u32 = 1;  // 设备已就绪
pub const DEV_ABSENT: u32 = 0;   // 设备不存在
