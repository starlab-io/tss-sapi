// Copyright 2017 Star Lab Corp.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![recursion_limit = "1024"]

#[macro_use]
extern crate enum_primitive_derive;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;
extern crate num_traits;
extern crate try_from;

mod errors;
pub mod utils;

#[allow(non_snake_case, non_camel_case_types, dead_code)]
#[allow(non_upper_case_globals, improper_ctypes)]
mod sys {
    use std::default::Default;
    use std::mem;
    use std::ptr;
    use try_from::TryFrom;

    include!("bindings.rs");

    // error values aren't getting pulled from sapi/tss2_common.h
    pub const TSS2_ERROR_LEVEL_MASK: TSS2_RC = 0xFF << TSS2_RC_LEVEL_SHIFT;
    pub const TSS2_TPM_ERROR_LEVEL: TSS2_RC = 0 << TSS2_RC_LEVEL_SHIFT;
    pub const TSS2_APP_ERROR_LEVEL: TSS2_RC = 5 << TSS2_RC_LEVEL_SHIFT;
    pub const TSS2_FEATURE_ERROR_LEVEL: TSS2_RC = 6 << TSS2_RC_LEVEL_SHIFT;
    pub const TSS2_ESAPI_ERROR_LEVEL: TSS2_RC = 7 << TSS2_RC_LEVEL_SHIFT;
    pub const TSS2_SYS_ERROR_LEVEL: TSS2_RC = 8 << TSS2_RC_LEVEL_SHIFT;
    pub const TSS2_SYS_PART2_ERROR_LEVEL: TSS2_RC = 9 << TSS2_RC_LEVEL_SHIFT;
    pub const TSS2_TCTI_ERROR_LEVEL: TSS2_RC = 10 << TSS2_RC_LEVEL_SHIFT;
    pub const TSS2_RESMGRTPM_ERROR_LEVEL: TSS2_RC = 11 << TSS2_RC_LEVEL_SHIFT;
    pub const TSS2_RESMGR_ERROR_LEVEL: TSS2_RC = 12 << TSS2_RC_LEVEL_SHIFT;
    pub const TSS2_DRIVER_ERROR_LEVEL: TSS2_RC = 13 << TSS2_RC_LEVEL_SHIFT;

    // values not pulled from sapi/tss2_tpm2_types.h
    // MAX_TPM_PROPERTIES = (MAX_CAP_DATA / sizeof(TPMS_TAGGED_PROPERTY))
    // MAX_CAP_DATA = (MAX_CAP_BUFFER - sizeof(TPM_CAP) - sizeof(UINT32)
    // TPM_CAP = typedef UINT32
    // MAX_CAP_BUFFER = 1024
    // TPMS_TAGGED_PROPERTY = struct { TPM_PT, UINT32 };
    // TPM_PT = typedef UINT32;
    // MAX_TPM_PROPERTIES = ((1024 - 4 - 4) / (4 + 4) = 127
    pub const MAX_TPM_PROPERTIES: UINT32 = 127;

    // TPM2B types must be initialized with the size parameter of the t union
    // set to the size of the buffer in the struct. The struct is made up
    // of the buffer + a UINT16 (the size). So it should be equal to the size
    // of the struct minus a UINT16.
    macro_rules! tpm2b_new(
        ($kind:ty) => (
            impl $kind {
                pub fn new() -> $kind {
                    let mut field: $kind = Default::default();
                    unsafe {
                        (*field.b.as_mut()).size =
                            (mem::size_of::<$kind>() - mem::size_of::<UINT16>()) as u16;
                    }
                    field
                }
            }
            )
        );

    tpm2b_new!(TPM2B_NAME);
    tpm2b_new!(TPM2B_NV_PUBLIC);
    tpm2b_new!(TPM2B_MAX_NV_BUFFER);

    // of the buffer + a UINT16 (the size). So it should be equal to the size
    // of the struct minus a UINT16.
    macro_rules! tpm2b_try_from(
        ($kind:ty, $lifetime:tt, $from:ty) => (
            impl<$lifetime> TryFrom<$from> for $kind {
                type Err = super::Error;

                fn try_from(data: $from) -> Result<$kind, Self::Err> {
                    let max = mem::size_of::<$kind>() - mem::size_of::<UINT16>();
                    ensure!(max >= data.len(),
                        super::ErrorKind::BadSize(format!("supplied data was {} bytes which \
                                            is larger than the available {} bytes",
                                            data.len(),
                                            max)));

                    let mut field: $kind = Default::default();
                    unsafe {
                        let mut thing = field.t.as_mut();
                        // set the length of incoming data
                        thing.size = data.len() as u16;
                        // copy the password into the password struct
                        ptr::copy(data.as_ptr(), thing.buffer.as_mut_ptr(), data.len());
                    }
                    Ok(field)
                }
            }
            )
        );

    // add try_from() method to TPM2B_AUTH that attempts to convert from
    // a buffer which is a password
    tpm2b_try_from!(TPM2B_AUTH, 'a, &'a[u8]);

    // create a new NV buffer from supplied data
    tpm2b_try_from!(TPM2B_MAX_NV_BUFFER, 'a, &'a[u8]);

    impl TPMS_AUTH_COMMAND {
        pub fn new() -> Self {
            // creates TPMS_AUTH_COMMAND initialized to an un"owned" password
            TPMS_AUTH_COMMAND { sessionHandle: TPM_RS_PW, ..Default::default() }
        }

        pub fn password(mut self, passwd: &Option<String>) -> super::Result<Self> {
            if let &Some(ref pass) = passwd {
                self.hmac = TPM2B_AUTH::try_from(pass.as_bytes())?;
            }

            Ok(self)
        }
    }

    macro_rules! nv_attrs(
        ($field:expr, $save:ident, $val:path) => (
            if $field {
                $save.bindgen_union_field += $val;
            }
            )
        );

    impl From<super::NvAttributes> for TPMA_NV {
        fn from(attrs: super::NvAttributes) -> Self {
            let mut built = TPMA_NV::default();

            nv_attrs!(attrs.ppread, built, TPMA_NV_TPMA_NV_PPREAD);
            nv_attrs!(attrs.ppwrite, built, TPMA_NV_TPMA_NV_PPWRITE);
            nv_attrs!(attrs.owner_read, built, TPMA_NV_TPMA_NV_OWNERREAD);
            nv_attrs!(attrs.owner_write, built, TPMA_NV_TPMA_NV_OWNERWRITE);
            nv_attrs!(attrs.auth_read, built, TPMA_NV_TPMA_NV_AUTHREAD);
            nv_attrs!(attrs.auth_write, built, TPMA_NV_TPMA_NV_AUTHWRITE);
            nv_attrs!(attrs.policy_read, built, TPMA_NV_TPMA_NV_POLICYREAD);
            nv_attrs!(attrs.policy_write, built, TPMA_NV_TPMA_NV_POLICYWRITE);
            nv_attrs!(attrs.policy_delete, built, TPMA_NV_TPMA_NV_POLICY_DELETE);
            nv_attrs!(attrs.read_locked, built, TPMA_NV_TPMA_NV_READLOCKED);
            nv_attrs!(attrs.write_locked, built, TPMA_NV_TPMA_NV_WRITELOCKED);
            nv_attrs!(attrs.written, built, TPMA_NV_TPMA_NV_WRITTEN);
            nv_attrs!(attrs.write_all, built, TPMA_NV_TPMA_NV_WRITEALL);
            nv_attrs!(attrs.write_define, built, TPMA_NV_TPMA_NV_WRITEDEFINE);
            nv_attrs!(attrs.read_stclear, built, TPMA_NV_TPMA_NV_READ_STCLEAR);
            nv_attrs!(attrs.write_stclear, built, TPMA_NV_TPMA_NV_WRITE_STCLEAR);
            nv_attrs!(attrs.clear_stclear, built, TPMA_NV_TPMA_NV_CLEAR_STCLEAR);
            nv_attrs!(attrs.global_lock, built, TPMA_NV_TPMA_NV_GLOBALLOCK);
            nv_attrs!(attrs.no_da, built, TPMA_NV_TPMA_NV_NO_DA);
            nv_attrs!(attrs.orderly, built, TPMA_NV_TPMA_NV_ORDERLY);
            nv_attrs!(attrs.platform_create, built, TPMA_NV_TPMA_NV_PLATFORMCREATE);

            built
        }
    }

    // masks not defined in the spec but defined in tpm2.0-tools/lib/rc-decode.h
    const TPM_RC_7BIT_ERROR_MASK: TSS2_RC = 0x7f;
    const TPM_RC_6BIT_ERROR_MASK: TSS2_RC = 0x3f;
    const TPM_RC_PARAMETER_MASK: TSS2_RC = 0xf00;
    const TPM_RC_HANDLE_MASK: TSS2_RC = 0x700;
    const TPM_RC_SESSION_MASK: TSS2_RC = 0x700;

    // bit positions for the different fields
    const TPM_RC_FORMAT_ONE: u8 = 7;

    fn is_bit_set(rc: TSS2_RC, pos: u8) -> bool {
        ((1 << pos) & rc) > 0
    }

    pub trait ErrorCodes {
        fn is_format_one(self) -> bool;
        fn get_code_fmt1(self) -> Self;
        fn get_code_ver1(self) -> Self;
    }

    impl ErrorCodes for TSS2_RC {
        fn is_format_one(self) -> bool {
            is_bit_set(self, TPM_RC_FORMAT_ONE)
        }

        fn get_code_fmt1(self) -> TSS2_RC {
            (self & TPM_RC_6BIT_ERROR_MASK) + RC_FMT1
        }

        fn get_code_ver1(self) -> TSS2_RC {
            (self & TPM_RC_7BIT_ERROR_MASK) + RC_VER1
        }
    }
}

pub use errors::*;
use num_traits::{FromPrimitive, ToPrimitive};
use std::cmp;
use std::default::Default;
use std::ffi::{CStr, CString};
use std::fmt;
use std::io;
use std::mem;
use std::ptr;
use sys::ErrorCodes;
use try_from::TryFrom;

fn malloc<T>(size: usize) -> *mut T {
    // use a Vec as our allocator
    let mut alloc: Vec<u8> = Vec::with_capacity(size);
    let ptr = alloc.as_mut_ptr() as *mut T;
    mem::forget(alloc);
    ptr
}

fn free<T>(mem: *mut T, size: usize) {
    unsafe { mem::drop(Vec::from_raw_parts(mem, 0, size)) }
}

macro_rules! tss_tpm_err(
    ($kind:path) => ( Err(ErrorKind::Tpm($kind).into()) )
);

macro_rules! tss_tcti_err(
    ($kind:path) => ( Err(ErrorKind::Tcti($kind).into()) )
);

fn tss_err(err: sys::TSS2_RC) -> Result<()> {
    // match against the error returned
    match err {
        // do nothing for success
        sys::TPM_RC_SUCCESS => Ok(()),
        // any error in the valid error range needs to be taken apart by layer
        val => {
            match val & sys::TSS2_ERROR_LEVEL_MASK {
                sys::TSS2_TPM_ERROR_LEVEL |
                sys::TSS2_SYS_PART2_ERROR_LEVEL => {
                    match val.is_format_one() {
                        true => {
                            // format one codes
                            match val.get_code_fmt1() {
                                sys::TPM_RC_ASYMMETRIC => {
                                    tss_tpm_err!(errors::tpm::ErrorKind::Asymmetric)
                                }
                                sys::TPM_RC_ATTRIBUTES => {
                                    tss_tpm_err!(errors::tpm::ErrorKind::Attributes)
                                }
                                sys::TPM_RC_HASH => tss_tpm_err!(errors::tpm::ErrorKind::Hash),
                                sys::TPM_RC_VALUE => tss_tpm_err!(errors::tpm::ErrorKind::Value),
                                sys::TPM_RC_HIERARCHY => {
                                    tss_tpm_err!(errors::tpm::ErrorKind::Hierarchy)
                                }
                                sys::TPM_RC_KEY_SIZE => {
                                    tss_tpm_err!(errors::tpm::ErrorKind::KeySize)
                                }
                                sys::TPM_RC_MGF => tss_tpm_err!(errors::tpm::ErrorKind::Mgf),
                                sys::TPM_RC_MODE => tss_tpm_err!(errors::tpm::ErrorKind::Mode),
                                sys::TPM_RC_TYPE => tss_tpm_err!(errors::tpm::ErrorKind::Type),
                                sys::TPM_RC_HANDLE => tss_tpm_err!(errors::tpm::ErrorKind::Handle),
                                sys::TPM_RC_KDF => tss_tpm_err!(errors::tpm::ErrorKind::Kdf),
                                sys::TPM_RC_RANGE => tss_tpm_err!(errors::tpm::ErrorKind::Range),
                                sys::TPM_RC_AUTH_FAIL => {
                                    tss_tpm_err!(errors::tpm::ErrorKind::AuthFail)
                                }
                                sys::TPM_RC_NONCE => tss_tpm_err!(errors::tpm::ErrorKind::Nonce),
                                sys::TPM_RC_PP => {
                                    tss_tpm_err!(errors::tpm::ErrorKind::PhysicalPresence)
                                }
                                sys::TPM_RC_SCHEME => tss_tpm_err!(errors::tpm::ErrorKind::Scheme),
                                sys::TPM_RC_SIZE => tss_tpm_err!(errors::tpm::ErrorKind::Size),
                                sys::TPM_RC_SYMMETRIC => {
                                    tss_tpm_err!(errors::tpm::ErrorKind::Symmetric)
                                }
                                sys::TPM_RC_TAG => tss_tpm_err!(errors::tpm::ErrorKind::Tag),
                                sys::TPM_RC_SELECTOR => {
                                    tss_tpm_err!(errors::tpm::ErrorKind::Selector)
                                }
                                sys::TPM_RC_INSUFFICIENT => {
                                    tss_tpm_err!(errors::tpm::ErrorKind::Insufficient)
                                }
                                sys::TPM_RC_SIGNATURE => {
                                    tss_tpm_err!(errors::tpm::ErrorKind::Signature)
                                }
                                sys::TPM_RC_KEY => tss_tpm_err!(errors::tpm::ErrorKind::Key),
                                sys::TPM_RC_POLICY_FAIL => {
                                    tss_tpm_err!(errors::tpm::ErrorKind::PolicyFail)
                                }
                                sys::TPM_RC_BAD_AUTH => {
                                    tss_tpm_err!(errors::tpm::ErrorKind::BadAuth)
                                }
                                err => {
                                    Err(ErrorKind::Tpm(errors::tpm::ErrorKind::FormatOne(err))
                                            .into())
                                }
                            }
                        }
                        false => {
                            // format zero uses "version 1" codes
                            match val.get_code_ver1() {
                                sys::TPM_RC_INITIALIZE => {
                                    tss_tpm_err!(errors::tpm::ErrorKind::Initialize)
                                }
                                sys::TPM_RC_FAILURE => {
                                    tss_tpm_err!(errors::tpm::ErrorKind::Failure)
                                }
                                sys::TPM_RC_DISABLED => {
                                    tss_tpm_err!(errors::tpm::ErrorKind::Disabled)
                                }
                                sys::TPM_RC_EXCLUSIVE => {
                                    tss_tpm_err!(errors::tpm::ErrorKind::Exclusive)
                                }
                                sys::TPM_RC_REBOOT => tss_tpm_err!(errors::tpm::ErrorKind::Reboot),
                                err => {
                                    Err(ErrorKind::Tpm(errors::tpm::ErrorKind::FormatZero(err))
                                            .into())
                                }
                            }
                        }
                    }
                }
                sys::TSS2_APP_ERROR_LEVEL => Err(ErrorKind::AppError(err).into()),
                sys::TSS2_FEATURE_ERROR_LEVEL => Err(ErrorKind::FeatureError(err).into()),
                sys::TSS2_ESAPI_ERROR_LEVEL => Err(ErrorKind::EsapiError(err).into()),
                sys::TSS2_TCTI_ERROR_LEVEL |
                sys::TSS2_SYS_ERROR_LEVEL => {
                    // get the error code
                    match val & !sys::TSS2_ERROR_LEVEL_MASK {
                        sys::TSS2_BASE_RC_GENERAL_FAILURE => {
                            tss_tcti_err!(errors::tcti::ErrorKind::GenFail)
                        }
                        sys::TSS2_BASE_RC_IO_ERROR => {
                            tss_tcti_err!(errors::tcti::ErrorKind::IoError)
                        }
                        err => {
                            Err(ErrorKind::Tcti(errors::tcti::ErrorKind::NotWrapped(err)).into())
                        }
                    }
                }
                sys::TSS2_RESMGRTPM_ERROR_LEVEL => Err(ErrorKind::ResMgrTpmError(err).into()),
                sys::TSS2_RESMGR_ERROR_LEVEL => Err(ErrorKind::ResMgrError(err).into()),
                sys::TSS2_DRIVER_ERROR_LEVEL => Err(ErrorKind::DriverError(err).into()),
                _ => Err(ErrorKind::Unknown(err).into()),
            }
        }
    }
}

/// abstract over TPMS_AUTH_COMMAND and its vector TSS2_SYS_CMD_AUTHS
struct CmdAuths {
    inner: sys::TSS2_SYS_CMD_AUTHS,
    _ptr: Box<*mut sys::TPMS_AUTH_COMMAND>,
    _data: Vec<sys::TPMS_AUTH_COMMAND>,
}

impl CmdAuths {
    pub fn new(mut cmds: Vec<sys::TPMS_AUTH_COMMAND>) -> Result<Self> {
        // found this limit in tpm2-tss/sysapi/sysapi/authorizations.c
        ensure!(cmds.len() <= sys::MAX_SESSION_NUM as usize,
                ErrorKind::Msg("Too many auth commands supplied".into()));

        let mut cmds_ptr = Box::new(cmds.as_mut_ptr());

        let inner = sys::TSS2_SYS_CMD_AUTHS {
            cmdAuthsCount: cmds.len() as u8,
            cmdAuths: &mut *cmds_ptr,
        };

        Ok(CmdAuths {
               inner: inner,
               _ptr: cmds_ptr,
               _data: cmds,
           })
    }
}

impl From<sys::TPMS_AUTH_COMMAND> for CmdAuths {
    fn from(cmd: sys::TPMS_AUTH_COMMAND) -> Self {
        CmdAuths::new(vec![cmd]).unwrap()
    }
}

/// abstract over TPMS_AUTH_RESPONSE and its vector TSS2_SYS_RSP_AUTHS
struct RespAuths {
    inner: sys::TSS2_SYS_RSP_AUTHS,
    _ptr: Box<*mut sys::TPMS_AUTH_RESPONSE>,
    _data: Vec<sys::TPMS_AUTH_RESPONSE>,
}

impl RespAuths {
    pub fn new(mut resps: Vec<sys::TPMS_AUTH_RESPONSE>) -> Result<Self> {
        ensure!(resps.len() < u8::max_value() as usize,
                ErrorKind::Msg("Too many auth responses supplied".into()));

        let mut resps_ptr = Box::new(resps.as_mut_ptr());

        let inner = sys::TSS2_SYS_RSP_AUTHS {
            rspAuthsCount: resps.len() as u8,
            rspAuths: &mut *resps_ptr,
        };

        Ok(RespAuths {
               inner: inner,
               _ptr: resps_ptr,
               _data: resps,
           })
    }
}

impl From<sys::TPMS_AUTH_RESPONSE> for RespAuths {
    fn from(resp: sys::TPMS_AUTH_RESPONSE) -> Self {
        RespAuths::new(vec![resp]).unwrap()
    }
}


/// Provide a handy enum that abstracts TPM algorithms
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Primitive)]
pub enum TpmAlgorithm {
    RSA = sys::TPM_ALG_RSA as isize,
    SHA1 = sys::TPM_ALG_SHA1 as isize,
    HMAC = sys::TPM_ALG_HMAC as isize,
    AES = sys::TPM_ALG_AES as isize,
    MGF1 = sys::TPM_ALG_MGF1 as isize,
    KEYEDHASH = sys::TPM_ALG_KEYEDHASH as isize,
    XOR = sys::TPM_ALG_XOR as isize,
    SHA256 = sys::TPM_ALG_SHA256 as isize,
    SHA384 = sys::TPM_ALG_SHA384 as isize,
    SHA512 = sys::TPM_ALG_SHA512 as isize,
    NULL = sys::TPM_ALG_NULL as isize,
    SM3_256 = sys::TPM_ALG_SM3_256 as isize,
    SM4 = sys::TPM_ALG_SM4 as isize,
    RSASSA = sys::TPM_ALG_RSASSA as isize,
    RSAES = sys::TPM_ALG_RSAES as isize,
    RSAPSS = sys::TPM_ALG_RSAPSS as isize,
    OAEP = sys::TPM_ALG_OAEP as isize,
    ECDSA = sys::TPM_ALG_ECDSA as isize,
    ECDH = sys::TPM_ALG_ECDH as isize,
    ECDAA = sys::TPM_ALG_ECDAA as isize,
    SM2 = sys::TPM_ALG_SM2 as isize,
    ECSCHNORR = sys::TPM_ALG_ECSCHNORR as isize,
    ECMQV = sys::TPM_ALG_ECMQV as isize,
    KDF1_SP800_56A = sys::TPM_ALG_KDF1_SP800_56A as isize,
    KDF2 = sys::TPM_ALG_KDF2 as isize,
    KDF1_SP800_108 = sys::TPM_ALG_KDF1_SP800_108 as isize,
    ECC = sys::TPM_ALG_ECC as isize,
    SYMCIPHER = sys::TPM_ALG_SYMCIPHER as isize,
    CAMELLIA = sys::TPM_ALG_CAMELLIA as isize,
    CTR = sys::TPM_ALG_CTR as isize,
    SHA3_256 = sys::TPM_ALG_SHA3_256 as isize,
    SHA3_384 = sys::TPM_ALG_SHA3_384 as isize,
    SHA3_512 = sys::TPM_ALG_SHA3_512 as isize,
    OFB = sys::TPM_ALG_OFB as isize,
    CBC = sys::TPM_ALG_CBC as isize,
    CFB = sys::TPM_ALG_CFB as isize,
    ECB = sys::TPM_ALG_ECB as isize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NvAttributes {
    pub ppread: bool,
    pub ppwrite: bool,
    pub owner_read: bool,
    pub owner_write: bool,
    pub auth_read: bool,
    pub auth_write: bool,
    pub policy_read: bool,
    pub policy_write: bool,
    pub policy_delete: bool,
    pub read_locked: bool,
    pub write_locked: bool,
    pub written: bool,
    pub write_all: bool,
    pub write_define: bool,
    pub read_stclear: bool,
    pub write_stclear: bool,
    pub clear_stclear: bool,
    pub global_lock: bool,
    pub no_da: bool,
    pub orderly: bool,
    pub platform_create: bool,
}

impl From<sys::TPMA_NV> for NvAttributes {
    fn from(nv: sys::TPMA_NV) -> Self {
        // get the attributes converted
        let nv_attrs = unsafe { nv.__bindgen_anon_1.as_ref() };

        NvAttributes {
            ppread: nv_attrs.TPMA_NV_PPREAD() > 0,
            ppwrite: nv_attrs.TPMA_NV_PPWRITE() > 0,
            owner_read: nv_attrs.TPMA_NV_OWNERREAD() > 0,
            owner_write: nv_attrs.TPMA_NV_OWNERWRITE() > 0,
            auth_read: nv_attrs.TPMA_NV_AUTHREAD() > 0,
            auth_write: nv_attrs.TPMA_NV_AUTHWRITE() > 0,
            policy_read: nv_attrs.TPMA_NV_POLICYREAD() > 0,
            policy_write: nv_attrs.TPMA_NV_POLICYWRITE() > 0,
            policy_delete: nv_attrs.TPMA_NV_POLICY_DELETE() > 0,
            read_locked: nv_attrs.TPMA_NV_READLOCKED() > 0,
            write_locked: nv_attrs.TPMA_NV_WRITELOCKED() > 0,
            written: nv_attrs.TPMA_NV_WRITTEN() > 0,
            write_all: nv_attrs.TPMA_NV_WRITEALL() > 0,
            write_define: nv_attrs.TPMA_NV_WRITEDEFINE() > 0,
            read_stclear: nv_attrs.TPMA_NV_READ_STCLEAR() > 0,
            write_stclear: nv_attrs.TPMA_NV_WRITE_STCLEAR() > 0,
            clear_stclear: nv_attrs.TPMA_NV_CLEAR_STCLEAR() > 0,
            global_lock: nv_attrs.TPMA_NV_GLOBALLOCK() > 0,
            no_da: nv_attrs.TPMA_NV_NO_DA() > 0,
            orderly: nv_attrs.TPMA_NV_ORDERLY() > 0,
            platform_create: nv_attrs.TPMA_NV_PLATFORMCREATE() > 0,
        }
    }
}

#[derive(Debug)]
pub struct NvRamArea<'ctx> {
    pub index: u32,
    pub size: u16,
    pub hash: TpmAlgorithm,
    pub attrs: NvAttributes,
    ctx: &'ctx Context,
    pos: u64,
}

impl<'ctx> NvRamArea<'ctx> {
    /// look up an NVRAM area
    pub fn get(ctx: &Context, index: u32) -> Result<NvRamArea> {
        let mut nv_name = sys::TPM2B_NAME::new();
        let mut nv_public = sys::TPM2B_NV_PUBLIC::default();

        trace!("Tss2_Sys_NV_ReadPublic({:?}, {}, 0, buffer, 0, name, 0)",
               ctx,
               index);
        tss_err(unsafe {
                    sys::Tss2_Sys_NV_ReadPublic(ctx.inner,
                                                index as sys::TPMI_RH_NV_INDEX,
                                                ptr::null(),
                                                &mut nv_public,
                                                &mut nv_name,
                                                ptr::null_mut())
                })?;

        let nv = unsafe { nv_public.t.as_ref() }.nvPublic;

        let hash = TpmAlgorithm::from_u32(nv.nameAlg as u32)
            .ok_or_else(|| ErrorKind::Msg("invalid TPM algorithm".into()))?;

        Ok(NvRamArea {
               index: nv.nvIndex,
               size: nv.dataSize,
               hash: hash,
               attrs: NvAttributes::from(nv.attributes),
               ctx: ctx,
               pos: 0,
           })
    }

    /// create an NVRAM area
    pub fn define(ctx: &Context,
                  index: u32,
                  size: u16,
                  hash: TpmAlgorithm,
                  attrs: NvAttributes)
                  -> Result<NvRamArea> {

        let mut nv = sys::TPM2B_NV_PUBLIC::new();

        // set our members
        let nvpub = sys::TPMS_NV_PUBLIC {
            nvIndex: index,
            nameAlg: hash.to_u16().unwrap(),
            attributes: attrs.into(),
            authPolicy: sys::TPM2B_DIGEST::default(),
            dataSize: size,
        };
        unsafe {
            (*nv.t.as_mut()).nvPublic = nvpub;
        }

        // create an auth command with our existing authentication password
        let cmd = sys::TPMS_AUTH_COMMAND::new().password(&ctx.passwd)?;
        // populate our session data from the auth command
        let session_data = CmdAuths::from(cmd);

        // create our NVRAM index password
        let mut auth = sys::TPM2B_AUTH::default();

        // create our session response
        let resp = sys::TPMS_AUTH_RESPONSE::default();
        let mut session_out = RespAuths::from(resp);

        trace!("Tss2_Sys_NV_DefineSpace({:?}, {}, {:?}, NULL index passwd, {:?}, SESSION_OUT)",
               ctx.inner,
               "TPM_RH_OWNER",
               session_data.inner,
               nv);
        tss_err(unsafe {
                    sys::Tss2_Sys_NV_DefineSpace(ctx.inner,
                                                 sys::TPM_RH_OWNER,
                                                 &session_data.inner,
                                                 &mut auth,
                                                 &mut nv,
                                                 &mut session_out.inner)
                })?;



        Ok(NvRamArea {
               index: nvpub.nvIndex,
               size: nvpub.dataSize,
               hash: hash,
               attrs: NvAttributes::from(nvpub.attributes),
               ctx: ctx,
               pos: 0,
           })
    }

    /// delete an NVRAM area
    pub fn undefine(self) -> Result<()> {
        // create an auth command with our existing authentication password
        let cmd = sys::TPMS_AUTH_COMMAND::new().password(&self.ctx.passwd)?;
        // populate our session data from the auth command
        let session_data = CmdAuths::from(cmd);

        trace!("Tss2_Sys_NV_UndefineSpace({:?}, {}, 0x{:08X}, {:?}, NULL)",
            self.ctx,
            "TPM_RH_OWNER",
            self.index,
            session_data.inner);
        tss_err(unsafe {
            sys::Tss2_Sys_NV_UndefineSpace(self.ctx.inner,
                                           sys::TPM_RH_OWNER,
                                           self.index,
                                           &session_data.inner,
                                           ptr::null_mut())
        })
    }

    fn write_chunk(&self,
                   session_data: &CmdAuths,
                   session_out: &mut RespAuths,
                   offset: u16,
                   data: &[u8])
                   -> Result<()> {
        let mut buf = sys::TPM2B_MAX_NV_BUFFER::try_from(data)?;

        trace!("Tss2_Sys_NV_Write({:?}, {}, {}, {:?}, {:?}, {}, SESSION_OUT)",
               self.ctx.inner,
               "TPM_RH_OWNER",
               self.index,
               session_data.inner,
               data,
               offset);
        tss_err(unsafe {
                    sys::Tss2_Sys_NV_Write(self.ctx.inner,
                                           sys::TPM_RH_OWNER,
                                           self.index,
                                           &session_data.inner,
                                           &mut buf,
                                           offset,
                                           &mut session_out.inner)
                })
    }

    fn read_chunk(&self,
                  session_data: &CmdAuths,
                  session_out: &mut RespAuths,
                  offset: u16,
                  read_req: u16)
                  -> Result<sys::TPM2B_MAX_NV_BUFFER> {

        let mut buf = sys::TPM2B_MAX_NV_BUFFER::new();

        let read_size = cmp::min(sys::MAX_NV_BUFFER_SIZE as u16, read_req);

        trace!("Tss2_Sys_NV_Read({:?}, {}, {}, {:?}, {}, {}, buf, SESSION_OUT)",
               self.ctx.inner,
               "TPM_RH_OWNER",
               self.index,
               session_data.inner,
               read_size,
               offset);

        tss_err(unsafe {
                    sys::Tss2_Sys_NV_Read(self.ctx.inner,
                                          sys::TPM_RH_OWNER,
                                          self.index,
                                          &session_data.inner,
                                          read_size,
                                          offset,
                                          &mut buf,
                                          &mut session_out.inner)
                })?;

        Ok(buf)
    }
}

impl<'ctx> fmt::Display for NvRamArea<'ctx> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f,
                 "NVRAM index      : 0x{:08X} ({})",
                 self.index,
                 self.index)?;
        writeln!(f, "Size             : {} (0x{:X})", self.size, self.size)?;
        writeln!(f,
                 "Hash algo        : {:?} (0x{:02X})",
                 self.hash,
                 self.hash as u16)?;
        writeln!(f, "Auth policy      : {}", "FIXME: unknown")?;
        writeln!(f, "Attributes       :")?;
        writeln!(f, "  PPREAD         : {}", self.attrs.ppread)?;
        writeln!(f, "  PPWRITE        : {}", self.attrs.ppwrite)?;
        writeln!(f, "  OwnerRead      : {}", self.attrs.owner_read)?;
        writeln!(f, "  OwnerWrite     : {}", self.attrs.owner_write)?;
        writeln!(f, "  AuthRead       : {}", self.attrs.auth_read)?;
        writeln!(f, "  AuthWrite      : {}", self.attrs.auth_write)?;
        writeln!(f, "  PolicyRead     : {}", self.attrs.policy_read)?;
        writeln!(f, "  PolicyWrit     : {}", self.attrs.policy_write)?;
        writeln!(f, "  PolicyDelete   : {}", self.attrs.policy_write)?;
        writeln!(f, "  ReadLocked     : {}", self.attrs.read_locked)?;
        writeln!(f, "  WriteLocked    : {}", self.attrs.write_locked)?;
        writeln!(f, "  Written        : {}", self.attrs.written)?;
        writeln!(f, "  WriteAll       : {}", self.attrs.write_all)?;
        writeln!(f, "  WriteDefine    : {}", self.attrs.write_define)?;
        writeln!(f, "  ReadSTClear    : {}", self.attrs.read_stclear)?;
        writeln!(f, "  WriteSTClear   : {}", self.attrs.write_stclear)?;
        writeln!(f, "  ClearSTClear   : {}", self.attrs.clear_stclear)?;
        writeln!(f, "  GlobalLock     : {}", self.attrs.global_lock)?;
        writeln!(f, "  NoDA           : {}", self.attrs.no_da)?;
        writeln!(f, "  Orderly        : {}", self.attrs.orderly)?;
        writeln!(f, "  PlatformCreate : {}", self.attrs.platform_create)?;
        Ok(())
    }
}

impl<'a> io::Write for NvRamArea<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        ensure!((self.pos as usize + buf.len()) <= self.size as usize,
                io::Error::new(io::ErrorKind::InvalidInput,
                               format!("offset {} + write size {} greater \
                                           than NVRAM area size {}",
                                       self.pos,
                                       buf.len(),
                                       self.size)));
        // create an auth command with our existing authentication password
        let cmd = sys::TPMS_AUTH_COMMAND::new().password(&self.ctx.passwd)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        // populate our session data
        let session_data = CmdAuths::from(cmd);
        let mut session_out = RespAuths::from(sys::TPMS_AUTH_RESPONSE::default());

        let chunk_size = sys::MAX_NV_BUFFER_SIZE;
        for chunk in buf.chunks(chunk_size as usize) {
            self.write_chunk(&session_data, &mut session_out, self.pos as u16, chunk)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            self.pos += chunk_size as u64;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> io::Seek for NvRamArea<'a> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let (base, offset) = match pos {
            io::SeekFrom::Start(val) => {
                self.pos = val;
                return Ok(val);
            }
            io::SeekFrom::End(val) => (self.size as u64, val),
            io::SeekFrom::Current(val) => (self.pos as u64, val),
        };

        let new_pos = if offset > 0 {
            base.checked_add(offset as u64)
        } else {
            base.checked_sub((offset.wrapping_neg()) as u64)
        };

        match new_pos {
            Some(n) if n <= self.size as u64 => {
                self.pos = n;
                Ok(n)
            }
            Some(n) => {
                Err(io::Error::new(io::ErrorKind::InvalidInput,
                                   format!("unable to seek to {}, which is past end \
                                           of NVRAM area at {}",
                                           n,
                                           self.size)))
            }
            None => {
                Err(io::Error::new(io::ErrorKind::InvalidInput,
                                   "invalid seek to a negative or overflow position"))
            }
        }
    }
}

impl<'a> io::Read for NvRamArea<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // create an auth command with our existing authentication password
        let cmd = sys::TPMS_AUTH_COMMAND::new().password(&self.ctx.passwd)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        // populate our session data
        let session_data = CmdAuths::from(cmd);
        let mut session_out = RespAuths::from(sys::TPMS_AUTH_RESPONSE::default());

        let mut total = 0;
        let mut to_read = self.size - self.pos as u16;
        trace!("reading {} bytes from index 0x{:08X}", to_read, self.index);
        while to_read > 0 {
            let chunk = self.read_chunk(&session_data, &mut session_out, self.pos as u16, to_read)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            let chunk_size = unsafe { chunk.t.as_ref().size };
            let mut chunk_slice = &unsafe { chunk.t.as_ref().buffer }[..chunk_size as usize];
            let n = io::Read::read(&mut chunk_slice, buf)?;
            trace!("read {} bytes from index 0x{:08X} at pos {}",
                   chunk_size,
                   self.index,
                   self.pos);
            if n == 0 {
                break;
            }
            self.pos += n as u64;
            to_read -= n as u16;
            total += n;
        }

        Ok(total as usize)
    }
}

#[derive(Clone, Debug)]
pub enum Startup {
    Clear,
    State,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Primitive)]
pub enum HierarchyAuth {
    Owner = sys::TPM_RH_OWNER as isize,
    Endorsement = sys::TPM_RH_ENDORSEMENT as isize,
    Lockout = sys::TPM_RH_LOCKOUT as isize,
}

#[derive(Clone, Debug)]
enum Capabilities {
    VariableProperties,
}

struct TpmProperties {
    index: usize,
    caps: sys::TPMU_CAPABILITIES,
}

impl Iterator for TpmProperties {
    type Item = sys::TPMS_TAGGED_PROPERTY;

    fn next(&mut self) -> Option<Self::Item> {
        let inner = unsafe { self.caps.tpmProperties.as_ref() };

        if self.index < inner.count as usize {
            let i = self.index;
            self.index += 1;
            inner.tpmProperty.get(i).cloned()
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct Context {
    inner: *mut sys::TSS2_SYS_CONTEXT,
    size: usize,
    _tcti: TctiContext, // need to keep this for the life of this context
    passwd: Option<String>, // the current authentication password
}

impl Drop for Context {
    fn drop(&mut self) {
        trace!("Tss2_Sys_Finalize({:?})", self.inner);
        unsafe {
            sys::Tss2_Sys_Finalize(self.inner);
        }
        trace!("Context free({:?})", self.inner);
        free(self.inner, self.size);
    }
}

impl Context {
    fn _new_context(tcti: TctiContext) -> Result<Context> {
        let mut abi = sys::TSS2_ABI_VERSION {
            tssCreator: sys::TSSWG_INTEROP,
            tssFamily: sys::TSS_SAPI_FIRST_FAMILY,
            tssLevel: sys::TSS_SAPI_FIRST_LEVEL,
            tssVersion: sys::TSS_SAPI_FIRST_VERSION,
        };

        let alloc_size = unsafe { sys::Tss2_Sys_GetContextSize(0) };
        ensure!(alloc_size != 0, "Invalid context size");

        let ptr = malloc::<sys::TSS2_SYS_CONTEXT>(alloc_size);

        trace!("Tss2_Sys_Initialize({:?}, {:?}, {:?}, {:?})",
               ptr,
               alloc_size,
               tcti.inner,
               abi);
        tss_err(unsafe { sys::Tss2_Sys_Initialize(ptr, alloc_size, tcti.inner, &mut abi) })?;

        Ok(Context {
               inner: ptr,
               size: alloc_size,
               _tcti: tcti,
               passwd: None,
           })
    }

    #[cfg(feature = "tcti-device")]
    pub fn device(dev: Option<&str>) -> Result<Context> {
        let tcti = TctiContext::device(dev)?;
        Self::_new_context(tcti)
    }

    #[cfg(feature = "tcti-socket")]
    pub fn socket(host: Option<&str>, port: Option<u16>) -> Result<Context> {
        let tcti = TctiContext::socket(host, port)?;
        Self::_new_context(tcti)
    }

    /// set the authentication password we will use
    pub fn password<T: ToString>(&mut self, passwd: T) {
        self.passwd = Some(passwd.to_string());
    }

    pub fn startup(&self, action: Startup) -> Result<()> {
        let action = match action {
            Startup::State => sys::TPM_SU_STATE,
            Startup::Clear => sys::TPM_SU_CLEAR,
        };

        trace!("Tss2_Sys_Startup({:?}, {:?})", self.inner, action);
        tss_err(unsafe { sys::Tss2_Sys_Startup(self.inner, action as u16) })?;
        Ok(())
    }

    fn get_cap(&self, req: Capabilities) -> Result<sys::TPMU_CAPABILITIES> {

        let (cap, prop, count) = match req {
            Capabilities::VariableProperties => {
                (sys::TPM_CAP_TPM_PROPERTIES, sys::PT_VAR, sys::MAX_TPM_PROPERTIES)
            }
        };

        let mut more_data: sys::TPMI_YES_NO = unsafe { mem::zeroed() };
        let mut cap_data: sys::TPMS_CAPABILITY_DATA = unsafe { mem::zeroed() };

        trace!("Tss2_Sys_GetCapability({:?}, NULL, ({:?}) {}, {}, {}, more_data, cap, NULL)",
               self.inner,
               req,
               cap,
               prop,
               count);
        tss_err(unsafe {
                    sys::Tss2_Sys_GetCapability(self.inner,
                                                ptr::null(),
                                                cap,
                                                prop,
                                                count,
                                                &mut more_data,
                                                &mut cap_data,
                                                ptr::null_mut())
                })?;

        Ok(cap_data.data)
    }

    fn get_variable_properties(&self) -> Result<TpmProperties> {
        let caps = self.get_cap(Capabilities::VariableProperties)?;

        Ok(TpmProperties {
               index: 0,
               caps: caps,
           })
    }

    /// check if the TPM is owned or not
    pub fn is_owned(&self) -> Result<bool> {
        // Get the variable TPM properties since this is how we see if the TPM is owned
        // filter those to the TPM_PT_PERMANENT ones convert those to the TPMA_PERMANENT
        // type which then allows us to check the 3 bits that we need to check
        let props = self.get_variable_properties()?;

        Ok(props.filter_map(|p| {
                if p.property == sys::TPM_PT_PERMANENT {
                    Some(unsafe {mem::transmute::<_, sys::TPMA_PERMANENT__bindgen_ty_1>(p.value) })
                } else {
                    None
                }
            }).map(|p| {
                // combine all the bits to see if this should be true or false
                p.ownerAuthSet() > 0 && p.endorsementAuthSet() > 0 && p.lockoutAuthSet() > 0
            }).all(|p| p)
           )
    }

    /// take ownership of the TPM setting the Owner, Endorsement or Lockout passwords to `passwd`
    pub fn take_ownership(&self, auth_type: HierarchyAuth, passwd: &str) -> Result<()> {
        // create an auth command with our existing authentication password
        let cmd = sys::TPMS_AUTH_COMMAND::new().password(&self.passwd)?;
        // populate our session data from the auth command
        let session_data = CmdAuths::from(cmd);

        // create our new password
        let mut new_auth = sys::TPM2B_AUTH::try_from(passwd.as_bytes())?;

        trace!("Tss2_Sys_HierarchyChangeAuth({:?}, {:?}, SESSION_DATA, NEW_AUTH, NULL)",
               self.inner,
               auth_type);
        tss_err(unsafe {
                    sys::Tss2_Sys_HierarchyChangeAuth(self.inner,
                                                      auth_type.to_u32().unwrap(),
                                                      &session_data.inner,
                                                      &mut new_auth,
                                                      ptr::null_mut())
                })?;
        Ok(())
    }
}

#[derive(Debug)]
struct TctiContext {
    inner: *mut sys::TSS2_TCTI_CONTEXT,
    size: usize,
}

impl Drop for TctiContext {
    fn drop(&mut self) {
        // technically we need to call tss2_tcti_finalize()
        // but that is a macro to look up a func pointer on
        // the opaque structure so we cannot without some helper
        // C code. The finalize step is minor in our use case and I
        // am OK with leaking the data until upstream addresses this.
        // see: https://github.com/01org/tpm2-tss/issues/490
        // see: https://github.com/01org/tpm2-tss/pull/491
        //trace!("Tss2_Tcti_Finalize({:?})", self.inner);
        //unsafe {
        //    sys::Tss2_Tcti_Finalize(self.inner);
        //}

        trace!("TctiContext free({:?})", self.inner);
        free(self.inner, self.size);
    }
}

impl TctiContext {
    #[cfg(feature = "tcti-device")]
    fn device(dev: Option<&str>) -> Result<TctiContext> {
        // if we didn't get a device path default to /dev/tpm0
        let dev_path = match dev {
            Some(dev) => CString::new(dev)?,
            None => CString::new("/dev/tpm0")?,
        };

        let config = sys::TCTI_DEVICE_CONF {
            device_path: dev_path.as_ptr(),
            logCallback: None,
            logData: ptr::null_mut(),
        };

        let mut alloc_size: usize = 0;

        tss_err(unsafe { sys::InitDeviceTcti(ptr::null_mut(), &mut alloc_size, &config) })?;

        let ptr = malloc::<sys::TSS2_TCTI_CONTEXT>(alloc_size);

        trace!("InitDeviceTcti({:?}, {:?}, {:?})", ptr, alloc_size, config);
        tss_err(unsafe { sys::InitDeviceTcti(ptr, &mut alloc_size, &config) })?;

        Ok(TctiContext {
               inner: ptr,
               size: alloc_size,
           })
    }

    #[cfg(feature = "tcti-socket")]
    fn socket(host: Option<&str>, port: Option<u16>) -> Result<TctiContext> {
        let host = match host {
            Some(name) => CString::new(name)?,
            None => {
                let def = unsafe { CStr::from_bytes_with_nul_unchecked(sys::DEFAULT_HOSTNAME) };
                def.to_owned()
            }
        };

        let port = match port {
            Some(num) => num,
            None => sys::DEFAULT_SIMULATOR_TPM_PORT as u16,
        };

        let config = sys::TCTI_SOCKET_CONF {
            hostname: host.as_ptr(),
            port: port,
            logCallback: None,
            logBufferCallback: None,
            logData: ptr::null_mut(),
        };

        let mut alloc_size: usize = 0;

        tss_err(unsafe { sys::InitSocketTcti(ptr::null_mut(), &mut alloc_size, &config, 0) })?;

        let ptr = malloc::<sys::TSS2_TCTI_CONTEXT>(alloc_size);

        trace!("InitSocketTcti({:?}, {:?}, {:?}, 0)",
               ptr,
               alloc_size,
               config);
        tss_err(unsafe { sys::InitSocketTcti(ptr, &mut alloc_size, &config, 0) })?;

        Ok(TctiContext {
               inner: ptr,
               size: alloc_size,
           })
    }
}
