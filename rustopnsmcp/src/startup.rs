//! Startup decisions that can be tested without running `main`.

/// Validate `--commit-confirm-default-mins` the way rustjunosmcp does: at
/// least one minute, and convertible to seconds without overflow.
///
/// # Errors
///
/// Returns a message naming the flag when the value is out of range.
pub fn validate_commit_confirm_default_mins(mins: u32) -> Result<u32, String> {
    if mins == 0 {
        return Err("--commit-confirm-default-mins must be >= 1".to_owned());
    }
    mins.checked_mul(60).ok_or_else(|| {
        "--commit-confirm-default-mins is too large to convert to seconds".to_owned()
    })
}

/// Refuse a flag that parses but that this build cannot honour yet.
///
/// mecmcp `docs/PACKAGING.md` §2: a flag that is present but ignored is worse
/// than one that is absent. `--commit-confirm-default-mins` only takes effect
/// with filter-rule commit-confirmed, which is not in this build. P5 removes
/// the refusal when it wires the flag.
///
/// `was_supplied` answers whether the operator typed a flag, by clap
/// argument id (`mecmcp_runtime::cli::ParsedCli::was_supplied`).
///
/// # Errors
///
/// Returns the refusal message when an unwired flag was supplied.
pub fn refuse_unwired_flags(was_supplied: &dyn Fn(&str) -> bool) -> Result<(), String> {
    if was_supplied("commit_confirm_default_mins") {
        return Err(
            "--commit-confirm-default-mins was supplied, but commit-confirmed apply is not \
             available in this build; remove the flag"
                .to_owned(),
        );
    }
    Ok(())
}

/// Create `path` holding 32 random bytes when nothing exists there.
///
/// An existing file is never rewritten, since rotating a good key would break
/// verification of every record already written under it. It is checked with
/// `mecmcp_secret::read_hardened_file` (no symlink, regular file, owner-only
/// mode, owned by the effective uid) and refused if it fails, because the
/// audit reader accepts any non-empty file. Linux only, as are all mechub MCP
/// servers, so there is no fallback entropy source.
///
/// # Errors
///
/// Returns a message naming the file when it cannot be created, an existing
/// file is unsafe, or the entropy source cannot be read. A half-written key
/// is removed.
pub fn ensure_audit_hmac_key(path: &std::path::Path) -> Result<(), String> {
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return mecmcp_secret::read_hardened_file(path, mecmcp_secret::FileLimits::default())
                .map(drop)
                .map_err(|error| {
                    format!(
                        "--audit-hmac-key-file {}: existing key is unsafe: {error}. Make it a \
                         regular file with `chmod 600` owned by the service user (`chown`)",
                        path.display()
                    )
                });
        }
        Err(error) => {
            return Err(format!(
                "--audit-hmac-key-file {}: cannot create the key: {error}. The LXC installer \
                 (packaging/lxc/install.sh) creates it; in a container mount a writable state \
                 directory",
                path.display()
            ));
        }
    };
    let mut key = [0u8; 32];
    let written = std::fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut key))
        .and_then(|()| file.write_all(&key));
    if let Err(error) = written {
        let _ = std::fs::remove_file(path);
        return Err(format!(
            "--audit-hmac-key-file {}: cannot write a generated key: {error}",
            path.display()
        ));
    }
    Ok(())
}

/// The audit subscriber configuration from the shared `--audit-*` and
/// `--otel-*` flags.
///
/// # Errors
///
/// Returns a message when `--audit-redact` does not parse.
pub fn audit_config(args: &mecmcp_runtime::cli::Cli) -> Result<mecmcp_audit::AuditConfig, String> {
    let redaction = if args.audit_redact.trim().is_empty() {
        None
    } else {
        Some(
            mecmcp_audit::AuditRedaction::parse(
                &args.audit_redact,
                args.audit_hmac_key_file.as_deref(),
            )
            .map_err(|error| format!("invalid --audit-redact: {error}"))?,
        )
    };
    Ok(mecmcp_audit::AuditConfig {
        format: mecmcp_audit::AuditFormat::parse(&args.audit_format),
        audit_log_file: args.audit_log_file.clone(),
        redaction,
        journald: args.audit_journald,
        // A build without the `otel` feature makes `init_tracing` refuse this
        // rather than run without the export.
        otel: args
            .otel_endpoint
            .clone()
            .map(|endpoint| mecmcp_audit::OtelConfig {
                endpoint,
                service_name: args.otel_service_name.clone(),
            }),
    })
}

/// The SSDF evidence pipeline configuration, or `None` when
/// `--ssdf-audit-endpoint` is absent.
///
/// # Errors
///
/// Returns the refusal for a half-configured pipeline. A server that starts
/// with one spools evidence it can never deliver.
pub fn evidence_config(
    args: &mecmcp_runtime::cli::Cli,
) -> Result<Option<mecmcp_audit::EvidenceConfig>, String> {
    args.evidence
        .into_config()
        .map_err(|error| format!("SSDF evidence configuration: {error}"))
}

/// The keyed approval-digest key, or `None` when
/// `--approval-digest-key-file` is absent.
///
/// # Errors
///
/// Returns a message naming the file when it fails the hardened read or is
/// shorter than 32 bytes.
pub fn approval_digest_key(
    args: &mecmcp_runtime::cli::Cli,
) -> Result<Option<mecmcp_changeset::ApprovalDigestKey>, String> {
    let Some(path) = args.approval_digest_key_file.as_deref() else {
        return Ok(None);
    };
    mecmcp_changeset::ApprovalDigestKey::load_from_file(path)
        .map(Some)
        .map_err(|error| format!("--approval-digest-key-file {}: {error}", path.display()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::cli::OpnsCli;
    use clap::Parser as _;

    fn common(args: &[&str]) -> mecmcp_runtime::cli::Cli {
        let mut argv = vec!["rustopnsmcp"];
        argv.extend_from_slice(args);
        OpnsCli::try_parse_from(argv).unwrap().common
    }

    #[test]
    fn otel_endpoint_reaches_the_audit_config() {
        let config = audit_config(&common(&[
            "--otel-endpoint",
            "http://127.0.0.1:4318",
            "--otel-service-name",
            "rustopnsmcp",
        ]))
        .unwrap();
        let otel = config.otel.expect("otel is configured, not dropped");
        assert_eq!(otel.endpoint, "http://127.0.0.1:4318");
        assert_eq!(otel.service_name, "rustopnsmcp");
        assert!(audit_config(&common(&[])).unwrap().otel.is_none());
    }

    #[test]
    fn a_half_configured_evidence_pipeline_refuses_startup() {
        assert!(evidence_config(&common(&[])).unwrap().is_none());
        let error = evidence_config(&common(&[
            "--ssdf-audit-endpoint",
            "https://127.0.0.1:8443",
        ]))
        .unwrap_err();
        assert!(error.contains("SSDF evidence configuration"), "{error}");
    }

    #[test]
    fn the_approval_digest_key_is_loaded_not_ignored() {
        use std::os::unix::fs::PermissionsExt as _;
        assert!(approval_digest_key(&common(&[])).unwrap().is_none());

        let dir = tempfile::tempdir().unwrap();
        let good = dir.path().join("digest.key");
        std::fs::write(&good, [7u8; 32]).unwrap();
        std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o600)).unwrap();
        let loaded = approval_digest_key(&common(&[
            "--approval-digest-key-file",
            good.to_str().unwrap(),
        ]))
        .unwrap();
        assert!(loaded.is_some());

        let short = dir.path().join("short.key");
        std::fs::write(&short, [7u8; 16]).unwrap();
        std::fs::set_permissions(&short, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            approval_digest_key(&common(&[
                "--approval-digest-key-file",
                short.to_str().unwrap(),
            ]))
            .is_err()
        );
    }

    #[test]
    fn commit_confirm_default_mins_must_be_at_least_one() {
        assert!(validate_commit_confirm_default_mins(0).is_err());
        assert_eq!(validate_commit_confirm_default_mins(10), Ok(600));
    }

    #[test]
    fn commit_confirm_default_mins_must_convert_to_seconds() {
        assert!(validate_commit_confirm_default_mins(u32::MAX).is_err());
    }

    #[test]
    fn supplying_commit_confirm_default_mins_refuses_startup_until_it_is_wired() {
        let error = refuse_unwired_flags(&|id| id == "commit_confirm_default_mins")
            .expect_err("a supplied, unwired flag must refuse startup");
        assert!(error.contains("--commit-confirm-default-mins"), "{error}");
    }

    #[test]
    fn nothing_supplied_starts() {
        assert!(refuse_unwired_flags(&|_| false).is_ok());
    }

    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn a_missing_key_is_created_32_bytes_and_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-hmac.key");
        ensure_audit_hmac_key(&path).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len(), 32);
        assert_ne!(bytes, vec![0u8; 32], "the key must be random, not zeroed");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn two_generated_keys_differ() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("a.key");
        let second = dir.path().join("b.key");
        ensure_audit_hmac_key(&first).unwrap();
        ensure_audit_hmac_key(&second).unwrap();
        assert_ne!(
            std::fs::read(first).unwrap(),
            std::fs::read(second).unwrap()
        );
    }

    #[test]
    fn an_existing_key_is_never_rewritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-hmac.key");
        std::fs::write(&path, b"installer-made-key-0123456789abcdef").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        ensure_audit_hmac_key(&path).unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"installer-made-key-0123456789abcdef"
        );
    }

    #[test]
    fn a_symlinked_key_is_refused_and_not_created_through() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("elsewhere");
        let link = dir.path().join("audit-hmac.key");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let message = ensure_audit_hmac_key(&link).unwrap_err();
        assert!(message.contains("chmod 600"), "{message}");
        assert!(!target.exists(), "must not create through a symlink");
    }

    #[test]
    fn a_world_readable_existing_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-hmac.key");
        std::fs::write(&path, [7u8; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let message = ensure_audit_hmac_key(&path).unwrap_err();
        assert!(message.contains("chmod 600"), "{message}");
    }

    #[test]
    fn an_uncreatable_key_names_the_installer() {
        let message = ensure_audit_hmac_key(std::path::Path::new(
            "/nonexistent-dir-for-test/audit-hmac.key",
        ))
        .unwrap_err();
        assert!(message.contains("audit-hmac.key"), "{message}");
        assert!(message.contains("install.sh"), "{message}");
    }
}
