#!/usr/bin/env bash
# shellcheck disable=SC2034 # the patterns are used by the scripts that source this file
# Sourced by the rig scripts. Operator-supplied values end up inside commands that a remote shell re-splits,
# so each is checked against a tight pattern first. The value is never echoed back.
alias_re='^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$'
token_name_re='^[A-Za-z0-9._-]{1,64}$'
abs_path_re='^/[A-Za-z0-9._/-]{1,200}$'
# require_match <what> <value> <regex>: exit 2 unless the value matches.
require_match() {
  [[ "${2-}" =~ $3 ]] || { echo "$1 is empty or has characters outside the allowed set; refusing" >&2; exit 2; }
}
tool_list_re='^[a-z_]+(,[a-z_]+)*$'
