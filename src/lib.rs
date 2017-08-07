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
}

pub use errors::*;
use std::ffi::{CStr, CString};
use std::mem;
use std::ptr;

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

        let result = unsafe { sys::Tss2_Sys_Initialize(ptr, alloc_size, tcti.inner, &mut abi) };
        ensure!(result == 0, "Unable to initialize context");

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

        let result = unsafe { sys::InitDeviceTcti(ptr::null_mut(), &mut alloc_size, &config) };
        ensure!(result == 0, "InitDeviceTcti failed to return a size");

        let ptr = malloc::<sys::TSS2_TCTI_CONTEXT>(alloc_size);

        let result = unsafe { sys::InitDeviceTcti(ptr, &mut alloc_size, &config) };
        ensure!(result == 0, "InitDeviceTcti failed to initialize");

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

        let result = unsafe { sys::InitSocketTcti(ptr::null_mut(), &mut alloc_size, &config, 0) };
        ensure!(result == 0, "InitSocketTcti failed to return a size");

        let ptr = malloc::<sys::TSS2_TCTI_CONTEXT>(alloc_size);

        let result = unsafe { sys::InitSocketTcti(ptr, &mut alloc_size, &config, 0) };
        ensure!(result == 0, "InitSocketTcti failed to initialize");

        Ok(TctiContext {
               inner: ptr,
               size: alloc_size,
           })
    }
}
