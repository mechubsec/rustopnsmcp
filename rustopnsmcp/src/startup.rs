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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

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
