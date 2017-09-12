pub mod tcti {
    error_chain! {
        errors {
            GenFail {
                description("general failure")
                display("general failure")
            }
            IoError {
                description("I/O failure")
                display("I/O failure")
            }
            NotWrapped(e: u32) {
                description("an unwrapped TCTI error")
                display("an unwrapped TCTI error: 0x{:08X}", e)
            }
        }
    }
}

pub mod tpm {
    error_chain! {
        errors {
            Asymmetric {
                description("asymmetric algorithm not supported or not correct")
                display("asymmetric algorithm not supported or not correct")
            }
            Attributes {
                description("inconsistent attributes")
                display("inconsistent attributes")
            }
            AuthFail {
                description("the authorization HMAC check failed and DA counter incremented")
                display("the authorization HMAC check failed and DA counter incremented")
            }
            BadAuth {
                description("authorization failure without DA implications")
                display("authorization failure without DA implications")
            }
            Disabled {
                description("TPM is disabled")
                display("TPM is disabled")
            }
            Failure {
                description("commands not accepted because of a TPM failure")
                display("commands not accepted because of a TPM failure")
            }
            Exclusive {
                description("command failed because audit sequence required exclusivity")
                display("command failed because audit sequence required exclusivity")
            }
            FormatOne(e: u32) {
                description("an unwrapped TPM format one error")
                display("an unwrapped TPM format one error: 0x{:02X}", e)
            }
            FormatZero(e: u32) {
                description("an unwrapped TPM format zero error")
                display("an unwrapped TPM format zero error: 0x{:02X}", e)
            }
            Handle {
                description("the handle is not correct for the use")
                display("the handle is not correct for the use")
            }
            Hash {
                description("hash algorithm not supported or not appropriate")
                display("hash algorithm not supported or not appropriate")
            }
            Hierarchy {
                description("hierarchy is not enabled or is not correct for the use")
                display("hierarchy is not enabled or is not correct for the use")
            }
            Initialize {
                description("TPM not initialized")
                display("TPM not initialized")
            }
            Insufficient {
                description("the TPM was unable to unmarshal a value\
                    because there were not enough objects in the input")
                display("the TPM was unable to unmarshal a value\
                    because there were not enough objects in the input")
            }
            Kdf {
                description(r#"unsupported key derivation function or
                    function not appropriate for use"#)
                display("unsupported key derivation function or function not appropriate for use")
            }
            Key {
                description("key fields are not compatible with the selected use")
                display("key fields are not compatible with the selected use")
            }
            KeySize {
                description("key size is not supported")
                display("key size is not supported")
            }
            Mgf {
                description("mask generation function not supported")
                display("mask generation function not supported")
            }
            Mode {
                description("mode of operation not supported")
                display("mode of operation not supported")
            }
            Nonce {
                description("invalid nonce size")
                display("invalid nonce size")
            }
            NvDefined {
                description("NV Index or persistend object already defined")
                display("NV Index or persistend object already defined")
            }
            NvLocked {
                description("NV access is locked")
                display("NV access is locked")
            }
            NvSpace {
                description("insufficient space for NV allocation")
                display("insufficient space for NV allocation")
            }
            NvUnavailable {
                description("command requires writing of NV and NV is not accessible")
                display("command requires writing of NV and NV is not accessible")
            }
            PhysicalPresence {
                description("auth requires assertion of physical presense")
                display("auth requires assertion of physical presense")
            }
            PolicyFail {
                description("a policy check failed")
                display("a policy check failed")
            }
            Range {
                description("value was out of allowed range")
                display("value was out of allowed range")
            }
            Reboot {
                description("TPM init and startup(clear) is required for TPM to resume operation")
                display("TPM init and startup(clear) is required for TPM to resume operation")
            }
            Scheme {
                description("unsupported or incompatible scheme")
                display("unsupported or incompatible scheme")
            }
            Selector {
                description("union selector is incorrect")
                display("union selector is incorrect")
            }
            Signature {
                description("the signature is not valid")
                display("the signature is not valid")
            }
            Size {
                description("structure is the wrong size")
                display("structure is the wrong size")
            }
            Symmetric {
                description("unsupported symmetric algorithm or key size")
                display("unsupported symmetric algorithm or key size")
            }
            Tag {
                description("incorrect structure tag")
                display("incorrect structure tag")
            }
            Type {
                description("the type of the value is not appropriate for the use")
                display("the type of the value is not appropriate for the use")
            }
            Value {
                description("value is out of range or is not correct for the context")
                display("value is out of range or is not correct for the context")
            }
        }
    }
}

error_chain! {
     foreign_links {
         Io(::std::io::Error);
         Null(::std::ffi::NulError);
     }
    links {
        Tpm(tpm::Error, tpm::ErrorKind);
        Tcti(tcti::Error, tcti::ErrorKind);
    }
    errors {
        AppError(e: u32) {
            description("unknown app level error")
            display("unknown app level error: 0x{:08X}", e)
        }
        BadSize(e: String) {
            description("invalid size provided")
            display("invalid size provided: {}", e)
        }
        FeatureError(e: u32) {
            description("unknown feature error")
            display("unknown app level error: 0x{:08X}", e)
        }
        EsapiError(e: u32) {
            description("unknown ESAPI error")
            display("unknown ESAPI error: 0x{:08X}", e)
        }
        ResMgrTpmError(e: u32) {
            description("unknown resource manager TPM error")
            display("unknown resource manager TPM error: 0x{:08X}", e)
        }
        ResMgrError(e: u32) {
            description("unknown resource manager error")
            display("unknown resource manager error: 0x{:08X}", e)
        }
        DriverError(e: u32) {
            description("unknown driver error")
            display("unknown driver error: 0x{:08X}", e)
        }
        Unknown(e: u32) {
            description("unknown error")
            display("unknown error: 0x{:08X}", e)
        }
    }
}
