//! Installed package files must not keep Unix modes from an untrusted zip.
//!
//! These tests fail while `ZipArchive::extract` applies the archive mode with
//! chmod. They pass once every extracted file is 0644 and every extracted
//! directory is 0755, including when the installing process umask is 0.

use std::convert::TryFrom;
use std::env;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use libwally::installation::InstallationContext;
use libwally::manifest::{Manifest, Realm};
use libwally::package_source::{PackageSource, PackageSourceMap, TestRegistry};
use libwally::resolution::resolve;
use libwally::test_package::PackageBuilder;

const LUA_BODY: &str = "return \"from-archive\"\n";
const TOOL_BODY: &str = "#!/bin/sh\necho from-archive\n";

/// Modes an archive can carry. The high bits are the Unix file type.
const FILE_SETUID_WORLD_WRITABLE: u32 = 0o104777;
const FILE_WORLD_WRITABLE: u32 = 0o100666;
const FILE_SETUID_EXECUTABLE: u32 = 0o104755;
const DIR_SETGID_WORLD_WRITABLE: u32 = 0o42777;

const SAFE_FILE_MODE: u32 = 0o644;
const SAFE_DIR_MODE: u32 = 0o755;

struct UmaskGuard {
    previous: u32,
}

impl UmaskGuard {
    fn zero() -> Self {
        Self {
            previous: set_umask(0),
        }
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        set_umask(self.previous);
    }
}

fn set_umask(mask: u32) -> u32 {
    extern "C" {
        fn umask(mask: u32) -> u32;
    }
    unsafe { umask(mask) }
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

struct ZipEntry {
    name: String,
    data: Vec<u8>,
    mode: u32,
}

/// Stored-method zip whose central-directory external attributes hold `mode`.
///
/// zip 0.5.11's `FileOptions::unix_permissions` keeps only `mode & 0o777`, so
/// this writer fills the external-attribute field directly. The layout matches
/// the local header, central header, and end-of-central-directory records
/// parsed by that crate.
fn stored_zip(entries: &[ZipEntry]) -> Vec<u8> {
    let mut local = Vec::new();
    let mut central = Vec::new();

    for entry in entries {
        let name = entry.name.as_bytes();
        assert!(name.len() <= u16::MAX as usize);
        let crc = crc32(&entry.data);
        let offset = u32::try_from(local.len()).unwrap();
        let size = u32::try_from(entry.data.len()).unwrap();

        local.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        local.extend_from_slice(&20u16.to_le_bytes());
        // UTF-8 name flag, matching zip's reader.
        local.extend_from_slice(&(1u16 << 11).to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&crc.to_le_bytes());
        local.extend_from_slice(&size.to_le_bytes());
        local.extend_from_slice(&size.to_le_bytes());
        local.extend_from_slice(&(name.len() as u16).to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(name);
        local.extend_from_slice(&entry.data);

        // Version made by: Unix (3) in the high byte, so `unix_mode` returns
        // the external attributes shifted down by 16.
        let version_made_by = (3u16 << 8) | 20;
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&version_made_by.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&(1u16 << 11).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&(entry.mode << 16).to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name);
    }

    let mut archive = local;
    let central_offset = u32::try_from(archive.len()).unwrap();
    let central_size = u32::try_from(central.len()).unwrap();
    archive.extend_from_slice(&central);
    let count = u16::try_from(entries.len()).unwrap();
    archive.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive.extend_from_slice(&count.to_le_bytes());
    archive.extend_from_slice(&count.to_le_bytes());
    archive.extend_from_slice(&central_size.to_le_bytes());
    archive.extend_from_slice(&central_offset.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive
}

fn package_zip() -> Vec<u8> {
    let manifest = "\
[package]
name = \"attacker/shared-payload\"
version = \"1.0.0\"
registry = \"http://localhost\"
realm = \"shared\"
";
    stored_zip(&[
        ZipEntry {
            name: "src/".into(),
            data: Vec::new(),
            mode: DIR_SETGID_WORLD_WRITABLE,
        },
        ZipEntry {
            name: "src/init.lua".into(),
            data: LUA_BODY.as_bytes().to_vec(),
            mode: FILE_SETUID_WORLD_WRITABLE,
        },
        ZipEntry {
            name: "nested/".into(),
            data: Vec::new(),
            mode: DIR_SETGID_WORLD_WRITABLE,
        },
        ZipEntry {
            name: "nested/lib.lua".into(),
            data: LUA_BODY.as_bytes().to_vec(),
            mode: FILE_WORLD_WRITABLE,
        },
        ZipEntry {
            name: "tool".into(),
            data: TOOL_BODY.as_bytes().to_vec(),
            mode: FILE_SETUID_EXECUTABLE,
        },
        ZipEntry {
            name: "wally.toml".into(),
            data: manifest.as_bytes().to_vec(),
            mode: FILE_WORLD_WRITABLE,
        },
    ])
}

fn write_index_manifest(registry: &Path, identity: &str, realm: Realm) {
    let manifest = PackageBuilder::new(identity)
        .with_realm(realm)
        .into_manifest();
    let name = manifest.package.name.clone();
    let path = registry.join("index").join(name.scope()).join(name.name());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, serde_json::to_string(&manifest).unwrap()).unwrap();

    let version = manifest.package.version.to_string();
    let contents = registry
        .join("contents")
        .join(name.scope())
        .join(name.name())
        .join(format!("{version}.zip"));
    fs::create_dir_all(contents.parent().unwrap()).unwrap();
    fs::write(contents, package_zip()).unwrap();
}

fn mode_bits(path: &Path) -> u32 {
    fs::metadata(path)
        .unwrap_or_else(|err| panic!("metadata {}: {err}", path.display()))
        .permissions()
        .mode()
        & 0o7777
}

fn assert_mode(path: &Path, expected: u32) {
    let actual = mode_bits(path);
    assert_eq!(
        actual,
        expected,
        "{} has mode {:04o}, expected {:04o}",
        path.display(),
        actual,
        expected
    );
}

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = env::temp_dir().join(format!("wally-unix-mode-{label}-{nanos}"));
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn install_forces_safe_modes_for_shared_server_and_dev_packages() {
    let _umask = UmaskGuard::zero();

    let registry = temp_dir("registry");
    write_index_manifest(&registry, "attacker/shared-payload@1.0.0", Realm::Shared);
    write_index_manifest(&registry, "attacker/server-payload@1.0.0", Realm::Server);
    write_index_manifest(&registry, "attacker/dev-payload@1.0.0", Realm::Dev);

    let project = temp_dir("project");
    let manifest = format!(
        r#"[package]
name = "victim/place"
version = "0.1.0"
registry = "{registry}"
realm = "server"

[dependencies]
SharedPayload = "attacker/shared-payload@1.0.0"

[server-dependencies]
ServerPayload = "attacker/server-payload@1.0.0"

[dev-dependencies]
DevPayload = "attacker/dev-payload@1.0.0"
"#,
        registry = registry.display()
    );
    fs::write(project.join("wally.toml"), &manifest).unwrap();

    let root = Manifest::load(&project).unwrap();
    let sources = PackageSourceMap::new(Box::new(PackageSource::TestRegistry(TestRegistry::new(
        &registry,
    ))));
    let resolved = resolve(&root, &Default::default(), &sources).unwrap();
    let root_id = root.package_id();
    InstallationContext::new(&project, None, None)
        .install(sources, root_id, resolved)
        .unwrap();

    let packages = [
        (
            project.join("Packages/_Index/attacker_shared-payload@1.0.0/shared-payload"),
            "shared",
        ),
        (
            project.join("ServerPackages/_Index/attacker_server-payload@1.0.0/server-payload"),
            "server",
        ),
        (
            project.join("DevPackages/_Index/attacker_dev-payload@1.0.0/dev-payload"),
            "dev",
        ),
    ];

    for (root_dir, realm) in &packages {
        let init = root_dir.join("src/init.lua");
        let lib = root_dir.join("nested/lib.lua");
        let tool = root_dir.join("tool");
        let manifest_path = root_dir.join("wally.toml");

        assert_eq!(
            fs::read_to_string(&init).unwrap(),
            LUA_BODY,
            "{realm} init.lua contents"
        );
        assert_eq!(
            fs::read_to_string(&lib).unwrap(),
            LUA_BODY,
            "{realm} lib.lua contents"
        );
        assert_eq!(
            fs::read_to_string(&tool).unwrap(),
            TOOL_BODY,
            "{realm} tool contents"
        );

        assert_mode(&init, SAFE_FILE_MODE);
        assert_mode(&lib, SAFE_FILE_MODE);
        assert_mode(&tool, SAFE_FILE_MODE);
        assert_mode(&manifest_path, SAFE_FILE_MODE);
        assert_mode(&root_dir.join("src"), SAFE_DIR_MODE);
        assert_mode(&root_dir.join("nested"), SAFE_DIR_MODE);
    }
}

#[test]
fn unpack_into_path_forces_safe_modes_with_umask_zero() {
    let _umask = UmaskGuard::zero();
    let output = temp_dir("unpack");
    let contents = libwally::package_contents::PackageContents::from_buffer(package_zip());
    contents.unpack_into_path(&output).unwrap();

    assert_eq!(
        fs::read_to_string(output.join("src/init.lua")).unwrap(),
        LUA_BODY
    );
    assert_mode(&output.join("src/init.lua"), SAFE_FILE_MODE);
    assert_mode(&output.join("nested/lib.lua"), SAFE_FILE_MODE);
    assert_mode(&output.join("tool"), SAFE_FILE_MODE);
    assert_mode(&output.join("wally.toml"), SAFE_FILE_MODE);
    assert_mode(&output.join("src"), SAFE_DIR_MODE);
    assert_mode(&output.join("nested"), SAFE_DIR_MODE);

    // A file created beside the archive entries must not be required for the
    // assertion above; this guards the test against a umask that is not 0.
    let mut probe = fs::File::create(output.join("umask-probe")).unwrap();
    probe.write_all(b"probe").unwrap();
    drop(probe);
    assert_eq!(
        mode_bits(&output.join("umask-probe")) & 0o022,
        0,
        "umask was not 0, so a create-only fix could look safe"
    );
}
