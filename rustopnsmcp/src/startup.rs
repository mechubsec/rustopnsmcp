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
}
