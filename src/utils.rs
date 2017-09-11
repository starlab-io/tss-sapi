use std::env;
use super::errors::*;
use super::Context;

/// Open a `Context` over a socket or the raw device based on the environment.
///
/// The TPM2 tools project relies on several environment variables to determine how
/// to open the TPM2 context. If the environment variable `TPM2TOOLS_TCTI_NAME` is not
/// present or has the value of "device" set, then a context is created pointing at
/// a local device, with the device name pulled from the `TPM2TOOLS_DEVICE_FILE`
/// environment variable.
///
/// If `TPM2TOOLS_TCTI_NAME` has the value "socket" set, then a context
/// is created using a socket. The `TPM2TOOLS_SOCKET_ADDRESS` environment variable
/// specifies the host to connect to and must be present. The `TPM2TOOLS_SOCKET_PORT`
/// environment variable specifies the port to connect to and is optional.
///
/// # Examples
///
/// ```
/// use tss_sapi::utils;
///
/// # fn foo() -> tss_sapi::Result<()> {
/// let context = utils::open_context_from_env()?;
/// # Ok(())
/// # }
/// ```
pub fn open_context_from_env() -> Result<Context> {
    // assume the device if the environment variable was not supplied
    let tcti = env::var("TPM2TOOLS_TCTI_NAME").unwrap_or_else(|_| String::from("device"));

    match tcti.as_str() {
        #[cfg(feature = "tcti-socket")]
        "socket" => {
            let addr = env::var("TPM2TOOLS_SOCKET_ADDRESS").ok();
            let port = match env::var("TPM2TOOLS_SOCKET_PORT").ok() {
                None => None,
                Some(v) => {
                    Some(v.parse::<u16>().chain_err(|| "Unable to parse TPM2TOOLS_SOCKET_PORT")?)
                }
            };

            // create a SAPI context and connect to the default TPM emulator
            Context::socket(addr.as_ref().map(|v| v.as_ref()), port)
                .chain_err(|| format!("Unable to connect to {:?}:{:?}", addr, port))
        }
        #[cfg(feature = "tcti-device")]
        "device" => {
            let dev = env::var("TPM2TOOLS_DEVICE_FILE").ok();

            // create a SAPI context and connect to the
            // device requested or the default device
            Context::device(dev.as_ref().map(|v| v.as_ref()))
                .chain_err(|| format!("Unable to connect to {:?}", dev))
        }
        _ => Err(ErrorKind::Msg("invalid TPM2TOOLS_TCTI_NAME value".into()).into()),
    }
}
