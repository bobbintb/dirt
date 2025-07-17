use std::env;
use std::path::PathBuf;

fn main() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bindings = out_path.join("bindings.rs");

    let builder = bindgen::Builder::default()
        .header("src/vmlinux.h")
        .derive_default(true)
        .derive_debug(true)
        .derive_copy(true)
        .use_core()
        .ctypes_prefix("::aya_ebpf::cty")
        .clang_arg("--target=bpf")
        .clang_arg("-D__BPF_TRACING__")
        .no_layout_tests()
        .raw_line("#![allow(non_upper_case_globals)]")
        .raw_line("#![allow(non_snake_case)]")
        .raw_line("#![allow(non_camel_case_types)]")
        .raw_line("#![allow(dead_code)]");

    let generated = builder.generate().expect("Unable to generate bindings");

    generated
        .write_to_file(&bindings)
        .expect("Couldn't write bindings!");
}
