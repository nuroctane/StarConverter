#[cfg(windows)]
include!("../../packaging/windows/resource.rs");

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        configure_windows_resource(
            "starconverter-gui",
            "starconverter-gui.exe",
            "StarConverter desktop utility",
        )?;
    }
    Ok(())
}

#[cfg(not(windows))]
fn main() {}
