// GM/T 0016-2012 智能密码钥匙密码应用接口 (SKF) 模拟动态库
// 库入口：声明所有模块并引入 FFI 导出

pub mod error_code;
pub mod types;
pub mod config;
pub mod key_mgr;
pub mod crypto;
pub mod skf_impl;
pub mod ffi;

// 引入 FFI 导出（使 #[no_mangle] 函数被编译进动态库）
// Reason: cdylib 需要引用这些模块，否则 no_mangle 函数可能被优化掉
#[allow(unused_imports)]
use ffi::device_ffi::*;
#[allow(unused_imports)]
use ffi::app_ffi::*;
#[allow(unused_imports)]
use ffi::container_ffi::*;
#[allow(unused_imports)]
use ffi::crypto_ffi::*;
#[allow(unused_imports)]
use ffi::stub_ffi::*;
