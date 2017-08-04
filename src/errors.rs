error_chain!{
    foreign_links {
        Io(::std::io::Error);
        Null(::std::ffi::NulError);
    }
}
