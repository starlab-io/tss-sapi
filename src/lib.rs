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
                                sys::TPM_RC_BAD_AUTH => tss_tpm_err!(errors::tpm::ErrorKind::BadAuth),
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
                                sys::TPM_RC_EXCLUSIVE => {
                                    tss_tpm_err!(errors::tpm::ErrorKind::Exclusive)
                                }
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

pub enum Startup {
    Clear,
    State,
}

enum HierarchyAuth {
    Owner,
    Endorsement,
    Lockout,
}

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
            ptr::copy(passwd.as_ptr(),
                      auth.buffer.as_mut_ptr(),
                      passwd.len());
        }

        let auth_handle = match auth_type {
            HierarchyAuth::Owner => sys::TPM_RH_OWNER,
            HierarchyAuth::Endorsement => sys::TPM_RH_ENDORSEMENT,
            HierarchyAuth::Lockout => sys::TPM_RH_LOCKOUT,
        };

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
        /*
        trace!("Tss2_Tcti_Finalize({:?})", self.inner);
        unsafe {
            sys::Tss2_Tcti_Finalize(self.inner);
        }
        */

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
