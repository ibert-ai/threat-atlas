use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("../..");
    let version_path = root.join("windows-soc-version.json");
    let icon = root.join("assets/atlassoc/sentinel/AtlasSOC.ico");
    println!("cargo:rerun-if-changed={}", version_path.display());
    println!("cargo:rerun-if-changed={}", icon.display());
    let metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(version_path).unwrap()).unwrap();
    let version = metadata["version"].as_str().unwrap();
    let parts: Vec<u16> = version
        .split('.')
        .map(|s| s.parse().expect("numeric SOC version"))
        .collect();
    assert_eq!(parts.len(), 3);
    let build = metadata["build"].as_u64().unwrap();
    assert!((1..=65535).contains(&build));
    println!("cargo:rustc-env=ATLAS_SOC_VERSION={version}");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    fs::write(
        out.join("soc_build.rs"),
        format!("pub const BUILD: u32 = {build};\n"),
    )
    .unwrap();
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    // Use the installed Microsoft Windows SDK; no downloaded resource compiler or new crate.
    let sdk_bin = PathBuf::from(env::var_os("ProgramFiles(x86)").expect("Windows SDK required"))
        .join("Windows Kits/10/bin");
    let mut compilers: Vec<_> = fs::read_dir(sdk_bin)
        .expect("Windows SDK bin directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path().join("x64/rc.exe"))
        .filter(|path| path.is_file())
        .collect();
    compilers.sort();
    let compiler = compilers.last().expect("Install Windows SDK with rc.exe");
    let rc = out.join("atlassoc.rc");
    let res = out.join("atlassoc.res");
    let icon_path = icon
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .replace('\\', "\\\\");
    let number = format!("{},{},{},{build}", parts[0], parts[1], parts[2]);
    let text = format!(
        r#"
1 ICON "{icon_path}"
1 VERSIONINFO
 FILEVERSION {number}
 PRODUCTVERSION {number}
 FILEOS 0x40004L
 FILETYPE 0x1L
BEGIN
 BLOCK "StringFileInfo"
 BEGIN
  BLOCK "040904b0"
  BEGIN
   VALUE "CompanyName", "Ibert Consulting\0"
   VALUE "FileDescription", "AtlasSOC by Ibert Consulting\0"
   VALUE "FileVersion", "{version}.{build}\0"
   VALUE "InternalName", "AtlasSOC\0"
   VALUE "OriginalFilename", "AtlasSOC.exe\0"
   VALUE "ProductName", "AtlasSOC\0"
   VALUE "ProductVersion", "{version} (build {build})\0"
  END
 END
 BLOCK "VarFileInfo"
 BEGIN
  VALUE "Translation", 0x409, 1200
 END
END
"#
    );
    fs::write(&rc, text).unwrap();
    assert!(
        Command::new(compiler)
            .arg("/nologo")
            .arg("/fo")
            .arg(&res)
            .arg(&rc)
            .status()
            .expect("Run Microsoft rc.exe")
            .success(),
        "SOC resources failed to compile"
    );
    // The screensaver binary retains its existing resource/entry-point behavior.
    println!(
        "cargo:rustc-link-arg-bin=threat-atlas-soc={}",
        res.display()
    );
}
