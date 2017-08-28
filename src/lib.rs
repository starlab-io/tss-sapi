// Copyright 2017 Star Lab Corp.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![recursion_limit = "1024"]

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;

mod errors;

#[allow(non_snake_case, non_camel_case_types, dead_code)]
#[allow(non_upper_case_globals, improper_ctypes)]
mod sys {
    use std::default::Default;
    use std::mem;

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

    // TPM2B_NAME must be initialized with the size parameter of the t union
    // set to the size of the buffer in the struct. The struct is made up
    // of the buffer + a UINT16 (the size). So it should be equal to the size
    // of the struct minus a UINT16.
    impl TPM2B_NAME {
        pub fn new() -> TPM2B_NAME {
            let mut field: TPM2B_NAME = Default::default();
            unsafe {
                (*field.t.as_mut()).size =
                    (mem::size_of::<TPM2B_NAME>() - mem::size_of::<UINT16>()) as u16;
            }
            field
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
use std::default::Default;
use std::ffi::{CStr, CString};
use std::mem;
use std::ptr;
use sys::ErrorCodes;

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

/// Provide a handy enum that abstracts TPM algorithms
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum TpmAlgorithm {
    RSA = sys::TPM_ALG_RSA,
    SHA1 = sys::TPM_ALG_SHA1,
    HMAC = sys::TPM_ALG_HMAC,
    AES = sys::TPM_ALG_AES,
    MGF1 = sys::TPM_ALG_MGF1,
    KEYEDHASH = sys::TPM_ALG_KEYEDHASH,
    XOR = sys::TPM_ALG_XOR,
    SHA256 = sys::TPM_ALG_SHA256,
    SHA384 = sys::TPM_ALG_SHA384,
    SHA512 = sys::TPM_ALG_SHA512,
    NULL = sys::TPM_ALG_NULL,
    SM3_256 = sys::TPM_ALG_SM3_256,
    SM4 = sys::TPM_ALG_SM4,
    RSASSA = sys::TPM_ALG_RSASSA,
    RSAES = sys::TPM_ALG_RSAES,
    RSAPSS = sys::TPM_ALG_RSAPSS,
    OAEP = sys::TPM_ALG_OAEP,
    ECDSA = sys::TPM_ALG_ECDSA,
    ECDH = sys::TPM_ALG_ECDH,
    ECDAA = sys::TPM_ALG_ECDAA,
    SM2 = sys::TPM_ALG_SM2,
    ECSCHNORR = sys::TPM_ALG_ECSCHNORR,
    ECMQV = sys::TPM_ALG_ECMQV,
    KDF1_SP800_56A = sys::TPM_ALG_KDF1_SP800_56A,
    KDF2 = sys::TPM_ALG_KDF2,
    KDF1_SP800_108 = sys::TPM_ALG_KDF1_SP800_108,
    ECC = sys::TPM_ALG_ECC,
    SYMCIPHER = sys::TPM_ALG_SYMCIPHER,
    CAMELLIA = sys::TPM_ALG_CAMELLIA,
    CTR = sys::TPM_ALG_CTR,
    SHA3_256 = sys::TPM_ALG_SHA3_256,
    SHA3_384 = sys::TPM_ALG_SHA3_384,
    SHA3_512 = sys::TPM_ALG_SHA3_512,
    OFB = sys::TPM_ALG_OFB,
    CBC = sys::TPM_ALG_CBC,
    CFB = sys::TPM_ALG_CFB,
    ECB = sys::TPM_ALG_ECB,
}

impl TpmAlgorithm {
    pub fn from_u32(x: u32) -> Option<TpmAlgorithm> {
        if x > sys::TPM_ALG_ERROR && x <= sys::TPM_ALG_LAST {
            Some(unsafe { mem::transmute(x) })
        } else {
            None
        }
    }
}

#[derive(Debug)]
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
pub struct NvRamArea {
    pub index: u32,
    pub size: u16,
    pub hash: u16,
    pub attrs: NvAttributes,
}

impl From<sys::TPM2B_NV_PUBLIC> for NvRamArea {
    fn from(nv_public: sys::TPM2B_NV_PUBLIC) -> Self {
        let nv = unsafe { nv_public.t.as_ref() }.nvPublic;

        NvRamArea {
            index: nv.nvIndex,
            size: nv.dataSize,
            hash: nv.nameAlg,
            attrs: NvAttributes::from(nv.attributes),
        }
    }
}

impl NvRamArea {
    /// look up an NVRAM area
    pub fn get(ctx: &Context, index: u32) -> Result<NvRamArea> {
        let mut nv_name = sys::TPM2B_NAME::new();
        let mut nv_public: sys::TPM2B_NV_PUBLIC = Default::default();

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

        Ok(NvRamArea::from(nv_public))
    }
}

#[derive(Clone, Debug)]
pub enum Startup {
    Clear,
    State,
}

#[derive(Clone, Debug)]
enum HierarchyAuth {
    Owner,
    Endorsement,
    Lockout,
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

        tss_err(unsafe { sys::Tss2_Sys_Initialize(ptr, alloc_size, tcti.inner, &mut abi) })?;

        Ok(Context {
               inner: ptr,
               size: alloc_size,
               _tcti: tcti,
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

    pub fn startup(&self, action: Startup) -> Result<()> {
        let action = match action {
            Startup::State => sys::TPM_SU_STATE,
            Startup::Clear => sys::TPM_SU_CLEAR,
        };

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

    fn take_ownership_helper(&self, auth_type: HierarchyAuth, passwd: &[u8]) -> Result<()> {
        let mut cmd = sys::TPMS_AUTH_COMMAND {
            sessionHandle: sys::TPM_RS_PW,
            nonce: unsafe { mem::zeroed() },
            hmac: unsafe { mem::zeroed() },
            sessionAttributes: unsafe { mem::zeroed() },
        };

        let mut cmds: *mut sys::TPMS_AUTH_COMMAND = &mut cmd;

        let session_data = sys::TSS2_SYS_CMD_AUTHS {
            cmdAuthsCount: 1,
            cmdAuths: &mut cmds,
        };

        let mut new_auth: sys::TPM2B_AUTH = Default::default();

        unsafe {
            let mut auth = new_auth.t.as_mut();
            // set the length of our password
            auth.size = passwd.len() as u16;
            // copy the password into the password struct
            ptr::copy(passwd.as_ptr(), auth.buffer.as_mut_ptr(), passwd.len());
        }

        let auth_handle = match auth_type {
            HierarchyAuth::Owner => sys::TPM_RH_OWNER,
            HierarchyAuth::Endorsement => sys::TPM_RH_ENDORSEMENT,
            HierarchyAuth::Lockout => sys::TPM_RH_LOCKOUT,
        };

        trace!("Tss2_Sys_HierarchyChangeAuth({:?}, {:?}, SESSION_DATA, NEW_AUTH, NULL)",
               self.inner,
               auth_type);
        tss_err(unsafe {
                    sys::Tss2_Sys_HierarchyChangeAuth(self.inner,
                                                      auth_handle,
                                                      &session_data,
                                                      &mut new_auth,
                                                      ptr::null_mut())
                })?;
        Ok(())
    }

    /// take ownership of the TPM setting the Owner, Endorsement and Lockout passwords to `passwd`
    pub fn take_ownership(&self, passwd: &str) -> Result<()> {
        self.take_ownership_helper(HierarchyAuth::Owner, passwd.as_bytes())?;
        self.take_ownership_helper(HierarchyAuth::Endorsement, passwd.as_bytes())?;
        self.take_ownership_helper(HierarchyAuth::Lockout, passwd.as_bytes())
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

        tss_err(unsafe { sys::InitSocketTcti(ptr, &mut alloc_size, &config, 0) })?;

        Ok(TctiContext {
               inner: ptr,
               size: alloc_size,
           })
    }
}
