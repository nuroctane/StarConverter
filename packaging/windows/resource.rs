use std::env;

use winresource::{VersionInfo, WindowsResource};

const COMPANY_NAME: &str = "Nur Octane";
const COPYRIGHT: &str = "Copyright (c) 2026 Nur Octane";
const PRODUCT_NAME: &str = "StarConverter";

fn configure_windows_resource(
    internal_name: &str,
    original_filename: &str,
    description: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let major = version_word("CARGO_PKG_VERSION_MAJOR")?;
    let minor = version_word("CARGO_PKG_VERSION_MINOR")?;
    let patch = version_word("CARGO_PKG_VERSION_PATCH")?;
    let numeric_version =
        (u64::from(major) << 48) | (u64::from(minor) << 32) | (u64::from(patch) << 16);
    let package_version = env::var("CARGO_PKG_VERSION")?;
    let dotted_version = format!("{package_version}.0");
    let manifest = application_manifest(internal_name, &dotted_version);

    let mut resource = WindowsResource::new();
    resource
        .set_language(0x0409)
        .set("CompanyName", COMPANY_NAME)
        .set("FileDescription", description)
        .set("FileVersion", &dotted_version)
        .set("InternalName", internal_name)
        .set("LegalCopyright", COPYRIGHT)
        .set("OriginalFilename", original_filename)
        .set("ProductName", PRODUCT_NAME)
        .set("ProductVersion", &dotted_version)
        .set_version_info(VersionInfo::FILEVERSION, numeric_version)
        .set_version_info(VersionInfo::PRODUCTVERSION, numeric_version)
        .set_version_info(VersionInfo::FILEFLAGS, VersionInfo::VS_FF_PRERELEASE)
        .set_manifest(&manifest)
        .compile()?;
    Ok(())
}

fn version_word(name: &str) -> Result<u16, Box<dyn std::error::Error>> {
    let value = env::var(name)?;
    Ok(value.parse()?)
}

fn application_manifest(internal_name: &str, dotted_version: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity name="io.github.nuroctane.{internal_name}" processorArchitecture="*" type="win32" version="{dotted_version}" />
  <description>StarConverter unsigned engineering pre-alpha</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}}" />
    </application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
    </windowsSettings>
  </application>
</assembly>
"#
    )
}
