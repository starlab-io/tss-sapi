# tss-sapi

TPM 2.0 TSS (TPM Software Stack) SAPI (System API) Rust Wrapper

## Build

To compile this library you must have tpm2-tss installed from https://github.com/01org/tpm2-tss

If you have it installed in a non-standard path you can export the following environment variables:

* `SAPI_LIBS_PATH` to where `libsapi.so` lives
* `TCTI_DEV_LIBS_PATH` to where `libtcti-device.so` lives
* `TCTI_SOCK_LIBS_PATH` to where `libtcti-socket.so` lives

Optionally you can also build with `--no-default-features` and then enable either `tcti-device` or `tcti-socket`.
