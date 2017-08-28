use std::env;
use tss_sapi::*;

pub fn open_context() -> Result<Context> {
    // assume the device if the environment variable was not supplied
    let tcti = env::var("TPM2TOOLS_TCTI_NAME").unwrap_or_else(|_| String::from("device"));

    match tcti.as_str() {
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
