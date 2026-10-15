#!/bin/bash
# Tests for setup.sh.
#
#     bash tests/test_setup.sh
#
# Separate from run_tests.py because the thing under test is shell. It covers
# the parts of the installer that cannot be checked by running the wizard:
# the config patcher, the [policies] section writer, the crontab block
# surgery, and the quoting of values that reach a config file or a shell.
#
# Nothing here touches the real crontab, the real config.ini or the network.

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$TESTS_DIR")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0

check() {
    local what="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        printf 'FAIL: %s\n      expected: %s\n      actual:   %s\n' \
            "$what" "$expected" "$actual" >&2
    fi
}

check_contains() {
    local what="$1" needle="$2" haystack="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        printf 'FAIL: %s\n      did not contain: %s\n' "$what" "$needle" >&2
    fi
}

check_lacks() {
    local what="$1" needle="$2" haystack="$3"
    if [[ "$haystack" != *"$needle"* ]]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        printf 'FAIL: %s\n      should not have contained: %s\n' "$what" "$needle" >&2
    fi
}

# Source the installer's functions with INSTALL_DIR redirected at scratch.
FMDRIFT_SETUP_LIB=1
# shellcheck source=../setup.sh
. "$ROOT/setup.sh"
INSTALL_DIR="$WORK"
mkdir -p "$WORK/backups"

status_of() { ( "$@" >/dev/null 2>&1 ); printf '%s' "$?"; }

# ------------------------------------------------------- the config patcher --

echo "== config patcher =="

cp "$ROOT/config.example.ini" "$WORK/config.ini"
TABLE_FILE="$WORK/table"
: > "$TABLE_FILE"
table_add firemon base_url     "https://fw.example.com"
table_add firemon username     "svc-drift"
table_add firemon verify_tls   "false"
table_add pair    primary      "FW-EAST"
table_add pair    secondary    "FW-WEST"
table_add filter  categories   "ESO*, SECURITY"
table_add email   recipients   "a@example.com,b@example.com"
table_add email   send_when    "always"
table_add filter  change_requests ""
table_add smtp    host         "relay.example.com"
table_add smtp    username     "mailer"
table_add smtp    from_address "drift@example.com"
table_add paths   state_dir    "/opt/drift/state"
patch_config "$WORK/config.ini" "$TABLE_FILE"

check "base_url patched"     "https://fw.example.com" "$(config_value "$WORK/config.ini" firemon base_url)"
check "firemon username"     "svc-drift"              "$(config_value "$WORK/config.ini" firemon username)"
check "smtp username kept apart" "mailer"             "$(config_value "$WORK/config.ini" smtp username)"
check "pair primary"         "FW-EAST"                "$(config_value "$WORK/config.ini" pair primary)"
check "categories"           "ESO*, SECURITY"         "$(config_value "$WORK/config.ini" filter categories)"
check "recipients"           "a@example.com,b@example.com" "$(config_value "$WORK/config.ini" email recipients)"
check "state_dir"            "/opt/drift/state"       "$(config_value "$WORK/config.ini" paths state_dir)"
check "untouched key kept"   "token"                  "$(config_value "$WORK/config.ini" firemon auth_mode)"
check "empty value has no trailing space" "change_requests =" "$(grep '^change_requests' "$WORK/config.ini")"
check "comments survive"     "1" "$(grep -c '^; Copy to config.ini' "$WORK/config.ini")"
check "regex with ; survives" 'cat:\s*([^;]*?)\s*;' "$(config_value "$WORK/config.ini" compare category_comment_pattern)"

# A key the example file no longer has must abort, writing nothing.
cp "$ROOT/config.example.ini" "$WORK/config2.ini"
: > "$TABLE_FILE"
table_add firemon no_such_key "x"
rc="$(status_of patch_config "$WORK/config2.ini" "$TABLE_FILE")"
check "missing key aborts"        "1" "$rc"
check "missing key writes nothing" "" "$(diff "$ROOT/config.example.ini" "$WORK/config2.ini")"
check "no .patched left behind"   "" "$(ls "$WORK"/*.patched 2>/dev/null)"

# ------------------------------------------------------- [policies] writer --

echo "== [policies] writer =="

cp "$ROOT/config.example.ini" "$WORK/config3.ini"
printf 'AZURE USE Transit = AZURE USW Transit\nKF-CLOUD-PREFILTER = KF-CLOUD-PREFILTER\n' > "$WORK/entries"
set_section_entries "$WORK/config3.ini" policies "$WORK/entries"
lines="$(config_section_lines "$WORK/config3.ini" policies)"
check "two live pairs written" "2" "$(printf '%s\n' "$lines" | grep -c '=')"
check_contains "pair one" "AZURE USE Transit = AZURE USW Transit" "$lines"
check "commented examples kept" "1" "$(grep -c '^;AZURE USE Transit' "$WORK/config3.ini")"
check "next section intact" "default" "$(config_value "$WORK/config3.ini" compare fields)"
# Entries land inside [policies], before [compare].
pol_line="$(grep -n '^\[policies\]' "$WORK/config3.ini" | cut -d: -f1)"
cmp_line="$(grep -n '^\[compare\]' "$WORK/config3.ini" | cut -d: -f1)"
ent_line="$(grep -n '^AZURE USE Transit = ' "$WORK/config3.ini" | cut -d: -f1)"
check "entry sits between the headers" "yes" "$([ "$ent_line" -gt "$pol_line" ] && [ "$ent_line" -lt "$cmp_line" ] && echo yes)"

# Re-running replaces, never appends.
printf 'Only One = Only One\n' > "$WORK/entries"
set_section_entries "$WORK/config3.ini" policies "$WORK/entries"
check "re-run replaces the entries" "Only One = Only One" "$(config_section_lines "$WORK/config3.ini" policies)"

# Empty entries file clears the section.
: > "$WORK/entries"
set_section_entries "$WORK/config3.ini" policies "$WORK/entries"
check "empty file clears the section" "" "$(config_section_lines "$WORK/config3.ini" policies)"

# ------------------------------------------------------------ pair sections --

echo "== pair sections =="

cp "$ROOT/config.example.ini" "$WORK/config4.ini"
pairs="$WORK/pairs.ini"; : > "$pairs"
append_pair_section "$pairs" "us-dr" "USE-FW" "USW-FW" "A = B, C = C" "ESO*" "" "" "a@example.com" "changes"
append_pair_section "$pairs" "apac" "AP-1" "AP-2" "" "" "" "" "" "never" "vendor_id"
check "two pair names" "us-dr
apac" "$(list_pair_names "$pairs")"
check "explicit all/none for empties" "policies        = all" "$(grep '^policies' "$pairs" | tail -n 1)"
check "recipients none when empty"    "recipients      = none" "$(grep '^recipients' "$pairs" | tail -n 1)"
insert_before_section "$WORK/config4.ini" compare "$pairs"
check "pairs land before [compare]" "yes" "$(awk '/^\[pair:us-dr\]/{p=NR} /^\[compare\]/{c=NR} END{print (p && c && p<c) ? "yes" : "no"}' "$WORK/config4.ini")"
check "pairs land after [pair]" "yes" "$(awk '/^\[pair\]/{p=NR} /^\[pair:us-dr\]/{c=NR} END{print (p && c && p<c) ? "yes" : "no"}' "$WORK/config4.ini")"
check "rest of file intact" "default" "$(config_value "$WORK/config4.ini" compare fields)"
extracted="$(extract_pair_sections "$WORK/config4.ini")"
check_contains "extract keeps pair sections" "[pair:apac]" "$extracted"
check_contains "extract keeps their keys"    "primary         = AP-1" "$extracted"
check_lacks    "extract drops [pair]"        "[pair]" "$extracted"
check_lacks    "extract drops [compare]"     "[compare]" "$extracted"
check_lacks    "extract drops commented examples" ";[pair:us-dr]" "$extracted"
printf '[policies:apac]\nX = Y\n' >> "$WORK/config4.ini"
check_contains "scoped sections extracted too" "[policies:apac]" "$(extract_pair_sections "$WORK/config4.ini")"
summary="$(pair_summary_lines "$WORK/config4.ini")"
check_contains "summary line for us-dr" "us-dr: USE-FW -> USW-FW | policies A = B, C = C | to a@example.com | send_when changes" "$summary"
check_contains "summary line for apac"  "apac: AP-1 -> AP-2 | policies all | to none | send_when never" "$summary"
check_lacks    "blank [pair] not summarised" "default:" "$summary"

# ------------------------------------------------------------ list parsing --

echo "== list parsing =="

check "email list normalised" "a@example.com,b@example.com" \
    "$( _parse_email_list ' a@example.com , b@example.com,, ' recipient 2>/dev/null )"
check "bad email refused" "1" "$(status_of _parse_email_list 'not-an-address' recipient)"
check "plain list normalised" "ESO*, SECURITY" "$( _parse_plain_list ' ESO* ,SECURITY ' category 2>/dev/null )"
check "plain list refuses ;" "1" "$(status_of _parse_plain_list 'a;b' category)"
summary="$( _parse_policy_pairs 'AZURE USE Transit = AZURE USW Transit, KF-CLOUD-PREFILTER' pair "$WORK/pairs" 2>/dev/null )"
check "pair summary" "AZURE USE Transit -> AZURE USW Transit; KF-CLOUD-PREFILTER -> KF-CLOUD-PREFILTER" "$summary"
check "pair file" "AZURE USE Transit = AZURE USW Transit
KF-CLOUD-PREFILTER = KF-CLOUD-PREFILTER" "$(cat "$WORK/pairs")"
check "pair refuses [" "1" "$(status_of _parse_policy_pairs 'a[b]=c' pair "$WORK/pairs2")"

check "reject_unsafe ' ;'" "1" "$(status_of reject_unsafe thing 'a ;b')"
check "reject_unsafe ok"   "0" "$(status_of reject_unsafe thing 'a-b_c 100%')"
check "yesno true"  "true"  "$(yesno_to_bool YES)"
check "yesno false" "false" "$(yesno_to_bool off)"

# --------------------------------------------------------- crontab surgery --

echo "== crontab surgery =="

existing='MAILTO=ops@example.com
0 1 * * * /usr/local/bin/backup.sh
'"$MARK_OPEN"'
old line
'"$MARK_CLOSE"'
'"$TRIM_OPEN"'
old trim
'"$TRIM_CLOSE"'
30 2 * * * /usr/local/bin/other.sh'

stripped="$(strip_block "$existing" "$MARK_OPEN" "$MARK_CLOSE")"
stripped="$(strip_block "$stripped" "$TRIM_OPEN" "$TRIM_CLOSE")"
check_lacks "managed block removed" "old line" "$stripped"
check_lacks "trim block removed"    "old trim" "$stripped"
check_contains "other jobs kept"    "backup.sh" "$stripped"
check_contains "later jobs kept"    "other.sh"  "$stripped"
check "trailing MAILTO found" "MAILTO=ops@example.com" "$(trailing_mailto "$stripped")"

unbalanced="$MARK_OPEN
x"
check "unbalanced markers refused" "2" "$(status_of strip_block "$unbalanced" "$MARK_OPEN" "$MARK_CLOSE")"

CRON_SPEC="0 6 * * *"
OPT_LOGROTATE=1
block="$(build_managed_block ' --dry-run' 'MAILTO=ops@example.com')"
check_contains "block opens"            "$MARK_OPEN"  "$block"
check_contains "block closes"           "$MARK_CLOSE" "$block"
check_contains "block empties MAILTO"   'MAILTO=""'   "$block"
check_contains "block restores MAILTO"  "MAILTO=ops@example.com" "$block"
check_contains "block runs run_drift"   "run_drift.py" "$block"
check_contains "block carries dry-run"  "--dry-run"    "$block"
check_contains "block has trim lines"   "$TRIM_OPEN"   "$block"
check_contains "trim paths quoted"      "\"$WORK/cron.log\"" "$block"
check "block ends with the close marker" "$MARK_CLOSE" "$(printf '%s\n' "$block" | tail -n 1)"

OPT_LOGROTATE=0
block="$(build_managed_block '' '')"
check_lacks "no trim block when off"   "$TRIM_OPEN"  "$block"
check_lacks "live block has no dry-run" "--dry-run"  "$block"
check_contains "no prior MAILTO -> note" "NOTE: MAILTO" "$block"

line="$(drift_cron_line ' --dry-run')"
check_contains "cron line quotes the config" "--config \"$WORK/config.ini\"" "$line"
check_contains "cron line sources secrets"   ". \"$WORK/secrets.env\""       "$line"
check_contains "cron line starts with spec"  "0 6 * * * "                     "$line"

# -------------------------------------------------------- add-recipient ----

echo "== add-recipient helpers =="

cp "$ROOT/config.example.ini" "$WORK/config5.ini"
pairs5="$WORK/pairs5.ini"; : > "$pairs5"
append_pair_section "$pairs5" "us-dr" "USE-FW" "USW-FW" "" "" "" "" "adam@example.com" "changes"
append_pair_section "$pairs5" "apac" "AP-1" "AP-2" "" "" "" "" "" "never"
insert_before_section "$WORK/config5.ini" compare "$pairs5"
# The single-pair shorthand [pair] also gets a primary, so "default" exists.
sed -i 's/^primary   =$/primary   = FW-EAST/; s/^secondary =$/secondary = FW-WEST/' "$WORK/config5.ini"

check "list_all_pair_names finds default and named pairs" "default
us-dr
apac" "$(list_all_pair_names "$WORK/config5.ini")"

check "find_pair_section: default" "pair" "$(find_pair_section "$WORK/config5.ini" "default")"
check "find_pair_section: case-insensitive" "pair:us-dr" "$(find_pair_section "$WORK/config5.ini" "US-DR")"
check "find_pair_section: unknown pair" "" "$(find_pair_section "$WORK/config5.ini" "nope")"
check "find_pair_section: default absent is empty" "" "$(find_pair_section "$ROOT/config.example.ini" "default")"

# merge_recipients: append, dedupe case-insensitively, and handle "none".
# Called as a plain statement, never via $(...) -- command substitution runs
# it in a subshell, and MERGE_ADDED_COUNT would then never reach the caller.
merge_recipients "adam@example.com" "boss@example.com"
check "merge appends a new address"       "adam@example.com, boss@example.com" "$MERGE_RESULT"
check "merge counts it as added"          "1" "$MERGE_ADDED_COUNT"

merge_recipients "adam@example.com" "ADAM@EXAMPLE.COM"
check "merge is case-insensitively idempotent" "adam@example.com" "$MERGE_RESULT"
check "merge counts nothing added"        "0" "$MERGE_ADDED_COUNT"

merge_recipients "none" "boss@example.com"
check "merge replaces 'none'"             "boss@example.com" "$MERGE_RESULT"
check "merge counts it as added from none" "1" "$MERGE_ADDED_COUNT"

merge_recipients "" "a@example.com,b@example.com"
check "merge from empty adds both"        "a@example.com, b@example.com" "$MERGE_RESULT"
check "merge counts both as added"        "2" "$MERGE_ADDED_COUNT"

merge_recipients "a@example.com,a@example.com" "a@example.com"
check "merge dedupes a repeated existing address too" "a@example.com" "$MERGE_RESULT"
check "merge counts the addition as not-new" "0" "$MERGE_ADDED_COUNT"

# The exact patch a real add-recipient run performs: read, merge, write.
TABLE_FILE="$WORK/table5"; : > "$TABLE_FILE"
section="$(find_pair_section "$WORK/config5.ini" "apac")"
current="$(config_value "$WORK/config5.ini" "$section" recipients)"
merge_recipients "$current" "mgr@example.com"
merged="$MERGE_RESULT"
table_add "$section" recipients "$merged"
table_add "$section" send_when "drift"
patch_config "$WORK/config5.ini" "$TABLE_FILE"
check "patched pair recipients" "mgr@example.com" "$(config_value "$WORK/config5.ini" "pair:apac" recipients)"
check "patched pair send_when"  "drift"           "$(config_value "$WORK/config5.ini" "pair:apac" send_when)"
check "other pair untouched"    "adam@example.com" "$(config_value "$WORK/config5.ini" "pair:us-dr" recipients)"
check "commented examples still intact" "1" "$(grep -c '^;AZURE USE Transit' "$WORK/config5.ini")"

# ------------------------------------------------------------- secrets.env --

echo "== secrets.env =="

tricky="it's \$HOME \`x\` \"q\" \\back"
write_secrets "$tricky" ""
check "secrets.env mode" "600" "$(stat -c '%a' "$WORK/secrets.env")"
recovered="$( unset FMDRIFT_PASSWORD; . "$WORK/secrets.env"; printf '%s' "$FMDRIFT_PASSWORD" )"
check "tricky password round-trips" "$tricky" "$recovered"
check_lacks "no smtp line when empty" "FMDRIFT_SMTP_PASSWORD" "$(cat "$WORK/secrets.env")"
write_secrets "p1" "smtp'pw"
recovered="$( unset FMDRIFT_SMTP_PASSWORD; . "$WORK/secrets.env"; printf '%s' "$FMDRIFT_SMTP_PASSWORD" )"
check "smtp password round-trips" "smtp'pw" "$recovered"
check "old secrets backed up" "1" "$(ls "$WORK/backups"/secrets-*.env.bak 2>/dev/null | wc -l)"

# --------------------------------------------------------------- mail queue --

echo "== mail queue =="

mailq() { printf 'Mail queue is empty\n'; }
check "empty queue" "0" "$(mail_queue_count)"
mailq() { printf -- '-Queue ID- --Size-- ----Arrival Time---- -Sender/Recipient-------\n4F1A2B3C4D  1234 Thu Sep 18 06:00:01  a@b.c\n-- 1 Kbytes in 1 Request.\n'; }
check "one queued" "1" "$(mail_queue_count)"
unset -f mailq

# -------------------------------------------------------------- pair editing --

echo "== pair editing =="

cp "$ROOT/config.example.ini" "$WORK/config6.ini"
p6="$WORK/p6"; : > "$p6"
append_pair_section "$p6" "us-dr" "USE-FW" "USW-FW" "A = B" "" "" "" "a@example.com" "changes"
append_pair_section "$p6" "apac" "AP-1" "AP-2" "" "" "" "" "" "never"
insert_before_section "$WORK/config6.ini" compare "$p6"
printf '\n[policies:apac]\nX = Y\n' >> "$WORK/config6.ini"

set_section_key "$WORK/config6.ini" "pair:us-dr" recipients "b@example.com"
check "set_section_key replaces a key"     "b@example.com" "$(config_value "$WORK/config6.ini" pair:us-dr recipients)"
set_section_key "$WORK/config6.ini" "pair:us-dr" primary_label "Prod"
check "set_section_key adds a missing key" "Prod" "$(config_value "$WORK/config6.ini" pair:us-dr primary_label)"
check "the added key is in its own section only" "" "$(config_value "$WORK/config6.ini" pair:apac primary_label)"
check "set_section_key leaves the other pair" "AP-1" "$(config_value "$WORK/config6.ini" pair:apac primary)"
check "set_section_key keeps the file loadable by section order" "us-dr
apac" "$(list_pair_names "$WORK/config6.ini")"
set_section_key "$WORK/config6.ini" "pair:apac" recipients ""
check "set_section_key writes an empty value" "" "$(config_value "$WORK/config6.ini" pair:apac recipients)"

remove_pair_sections "$WORK/config6.ini" "APAC"
check "remove_pair_sections drops the pair (case-insensitive)" "" "$(find_pair_section "$WORK/config6.ini" apac)"
check "remove_pair_sections drops its scoped sections" "" "$(config_value "$WORK/config6.ini" policies:apac X)"
check "remove_pair_sections keeps the other pair" "USE-FW" "$(config_value "$WORK/config6.ini" pair:us-dr primary)"
check "remove_pair_sections keeps [compare]" "default" "$(config_value "$WORK/config6.ini" compare fields)"
check "pair_state_file slug" "last-us_dr_pair_1.json" "$(basename "$(pair_state_file 'us dr/pair:1')")"

# The verbs end to end, unattended, with the report itself stubbed out.
INSTALL_DIR="$WORK/inst"; mkdir -p "$INSTALL_DIR/state"
cp "$ROOT/config.example.ini" "$INSTALL_DIR/config.example.ini"
cp "$ROOT/config.example.ini" "$INSTALL_DIR/config.ini"
printf 'FMDRIFT_PASSWORD=x\n' > "$INSTALL_DIR/secrets.env"
run_drift() { return 0; }
_run_candidate() { return 0; }
OPT_YES=1; POSITIONAL_ARG=""; PAIRS=()
export FMDRIFT_SETUP_PAIR1_NAME=ha FMDRIFT_SETUP_PAIR1_PRIMARY=FW-1 FMDRIFT_SETUP_PAIR1_SECONDARY=FW-2 \
       FMDRIFT_SETUP_PAIR1_POLICIES=all FMDRIFT_SETUP_PAIR1_MATCH_BY=vendor_id FMDRIFT_SETUP_LIST_PROPERTIES=no \
       FMDRIFT_SETUP_PAIR1_CATEGORIES=all FMDRIFT_SETUP_PAIR1_CHANGE_REQUESTS=none FMDRIFT_SETUP_PAIR1_APPLICATIONS=none \
       FMDRIFT_SETUP_PAIR1_RECIPIENTS=ops@example.com FMDRIFT_SETUP_PAIR1_SEND_WHEN=drift
out="$( (do_add_pair) 2>&1 )"; rc=$?
check "add-pair exits 0" "0" "$rc"
check "add-pair wrote the devices" "FW-1" "$(config_value "$INSTALL_DIR/config.ini" pair:ha primary)"
check "add-pair wrote match_by" "vendor_id" "$(config_value "$INSTALL_DIR/config.ini" pair:ha match_by)"
check "add-pair wrote recipients" "ops@example.com" "$(config_value "$INSTALL_DIR/config.ini" pair:ha recipients)"
check "add-pair backed the config up" "1" "$(ls "$INSTALL_DIR/backups"/config-*.ini.bak 2>/dev/null | wc -l)"
check "add-pair leaves no candidate behind" "0" "$([ -e "$INSTALL_DIR/config.ini.new" ] && echo 1 || echo 0)"
check "add-pair config mode 600" "600" "$(stat -c '%a' "$INSTALL_DIR/config.ini")"
out="$( (do_add_pair) 2>&1 )"; rc=$?
check "add-pair refuses a duplicate name" "1" "$rc"
check_contains "duplicate is explained" "already exists" "$out"

export FMDRIFT_SETUP_PAIR1_RECIPIENTS="ops@example.com, boss@example.com" FMDRIFT_SETUP_PAIR1_SEND_WHEN=changes \
       FMDRIFT_SETUP_TARGET_PAIR=HA
: > "$INSTALL_DIR/state/last-ha.json"
sleep 1
out="$( (do_edit_pair) 2>&1 )"; rc=$?
check "edit-pair exits 0" "0" "$rc"
check "edit-pair changed recipients" "ops@example.com,boss@example.com" "$(config_value "$INSTALL_DIR/config.ini" pair:ha recipients)"
check "edit-pair changed send_when" "changes" "$(config_value "$INSTALL_DIR/config.ini" pair:ha send_when)"
check "edit-pair kept the devices" "FW-2" "$(config_value "$INSTALL_DIR/config.ini" pair:ha secondary)"
check "edit-pair kept match_by" "vendor_id" "$(config_value "$INSTALL_DIR/config.ini" pair:ha match_by)"
check "edit-pair backed the config up again" "2" "$(ls "$INSTALL_DIR/backups"/config-*.ini.bak 2>/dev/null | wc -l)"
out="$( (do_edit_pair) 2>&1 )"; rc=$?
check "edit-pair with nothing changed exits 0" "0" "$rc"
check_contains "edit-pair says nothing changed" "nothing changed" "$out"

out="$( (do_remove_pair) 2>&1 )"; rc=$?
check "remove-pair exits 0" "0" "$rc"
check "remove-pair dropped the section" "" "$(find_pair_section "$INSTALL_DIR/config.ini" ha)"
check "remove-pair dropped the state file" "0" "$([ -e "$INSTALL_DIR/state/last-ha.json" ] && echo 1 || echo 0)"
check_contains "remove-pair warned it was the last pair" "only pair" "$out"
FMDRIFT_SETUP_TARGET_PAIR=nope
out="$( (do_remove_pair) 2>&1 )"; rc=$?
check "remove-pair of an unknown pair fails" "1" "$rc"

unset FMDRIFT_SETUP_PAIR1_NAME FMDRIFT_SETUP_PAIR1_PRIMARY FMDRIFT_SETUP_PAIR1_SECONDARY FMDRIFT_SETUP_PAIR1_POLICIES \
      FMDRIFT_SETUP_PAIR1_MATCH_BY FMDRIFT_SETUP_LIST_PROPERTIES FMDRIFT_SETUP_PAIR1_CATEGORIES \
      FMDRIFT_SETUP_PAIR1_CHANGE_REQUESTS FMDRIFT_SETUP_PAIR1_APPLICATIONS FMDRIFT_SETUP_PAIR1_RECIPIENTS \
      FMDRIFT_SETUP_PAIR1_SEND_WHEN FMDRIFT_SETUP_TARGET_PAIR
unset -f run_drift _run_candidate
OPT_YES=0; EXTRA_NAMES_FILE=""
INSTALL_DIR="$WORK"

# ------------------------------------------------------------------- update --

echo "== update =="

check "version_newer 1.1.0 > 1.0.0"   "0" "$(status_of version_newer 1.1.0 1.0.0)"
check "version_newer 1.0.0 !> 1.1.0"  "1" "$(status_of version_newer 1.0.0 1.1.0)"
check "version_newer 1.10.0 > 1.9.0"  "0" "$(status_of version_newer 1.10.0 1.9.0)"
check "version_newer equal is not newer" "1" "$(status_of version_newer 1.0.0 1.0.0)"
check "version_newer empty is not newer" "1" "$(status_of version_newer '' 1.0.0)"

# A fake install: the real program files plus an operator's config and state.
UPD="$WORK/upd"
mkdir -p "$UPD/state" "$UPD/out" "$UPD/firemon_drift"
for f in "${UPDATE_FILES[@]}"; do cp -R "$ROOT/$f" "$UPD/$f"; done
printf '__version__ = "0.9.0"\n' > "$UPD/firemon_drift/__init__.py"
printf '[firemon]\nbase_url = https://keep.me\n' > "$UPD/config.ini"
printf 'FMDRIFT_PASSWORD=keep\n' > "$UPD/secrets.env"
printf '{"fingerprints": []}\n' > "$UPD/state/last-default.json"
mkdir -p "$UPD/firemon_drift/__pycache__"; : > "$UPD/firemon_drift/__pycache__/stale.pyc"
check "installed_version reads the file" "0.9.0" "$(installed_version "$UPD")"

# The release on offer: a copy of the tree with a bumped version, as a dir,
# a tarball with GitHub's wrapper directory, and a zip.
REL="$WORK/rel/FireMon-Policy-Drift-main"
mkdir -p "$REL"
for f in "${UPDATE_FILES[@]}"; do cp -R "$ROOT/$f" "$REL/$f"; done
printf '__version__ = "9.9.9"\n' > "$REL/firemon_drift/__init__.py"
printf '# new readme\n' > "$REL/README.md"
( cd "$WORK/rel" && tar -czf "$WORK/release.tar.gz" FireMon-Policy-Drift-main )

INSTALL_DIR="$UPD"
OPT_SOURCE="$REL"
scratch="$(mktemp -d)"
check "fetch from a directory" "$REL" "$(update_fetch "$scratch")"
OPT_SOURCE="$WORK/release.tar.gz"
got="$(update_fetch "$scratch")"
check "fetch from a tarball finds the wrapped root" "9.9.9" "$(installed_version "$got")"
OPT_SOURCE="$WORK/nothing-here.tar.gz"
check "fetch from a missing path fails" "1" "$(status_of update_fetch "$scratch")"
rm -rf "$scratch"

backup="$(update_backup)"
check "backup archive created" "1" "$([ -f "$backup" ] && echo 1 || echo 0)"
check "backup holds the old package" "firemon_drift/__init__.py" "$(tar -tzf "$backup" | grep -x 'firemon_drift/__init__.py')"
check "backup leaves config alone" "" "$(tar -tzf "$backup" | grep -x 'config.ini')"

update_apply "$REL"
check "apply returns 0" "0" "$?"
check "package replaced" "9.9.9" "$(installed_version "$UPD")"
check "readme replaced" "# new readme" "$(cat "$UPD/README.md")"
check "config kept" "https://keep.me" "$(sed -n 's/^base_url = //p' "$UPD/config.ini")"
check "secrets kept" "FMDRIFT_PASSWORD=keep" "$(cat "$UPD/secrets.env")"
check "state kept" "1" "$([ -f "$UPD/state/last-default.json" ] && echo 1 || echo 0)"
check "stale pycache dropped" "0" "$([ -d "$UPD/firemon_drift/__pycache__" ] && echo 1 || echo 0)"
check "no .new or .old left behind" "" "$(ls -d "$UPD"/*.new "$UPD"/*.old 2>/dev/null)"
check "setup.sh executable" "1" "$([ -x "$UPD/setup.sh" ] && echo 1 || echo 0)"

update_rollback "$backup"
check "rollback restores the package" "0.9.0" "$(installed_version "$UPD")"
check "rollback keeps config" "https://keep.me" "$(sed -n 's/^base_url = //p' "$UPD/config.ini")"
check "rollback of an empty archive path fails" "1" "$(status_of update_rollback '')"

# The whole verb, unattended, with the self-test stubbed: pass, then fail.
OPT_SOURCE="$WORK/release.tar.gz"; OPT_YES=1; OPT_CHECK=0
update_selftest() { return 0; }
out="$(do_update 2>&1)"
check "do_update succeeds" "9.9.9" "$(installed_version "$UPD")"
check_contains "do_update reports the version" "now at version 9.9.9" "$out"
check_contains "do_update names the backup" "backups/code-" "$out"

printf '__version__ = "0.9.0"\n' > "$UPD/firemon_drift/__init__.py"
update_selftest() { printf 'boom\n' > "$INSTALL_DIR/.tests.err"; return 1; }
out="$( (do_update) 2>&1 )"; rc=$?
check "failed self-test exits 1" "1" "$rc"
check "failed self-test rolls back" "0.9.0" "$(installed_version "$UPD")"
check_contains "failure is explained" "rolled back" "$out"
check_contains "test output shown" "boom" "$out"

OPT_CHECK=1; update_selftest() { return 0; }
printf '__version__ = "0.9.0"\n' > "$UPD/firemon_drift/__init__.py"
out="$(do_update 2>&1)"
check_contains "--check reports availability" "update available" "$out"
check "--check changes nothing" "0.9.0" "$(installed_version "$UPD")"
printf '__version__ = "9.9.9"\n' > "$UPD/firemon_drift/__init__.py"
out="$(do_update 2>&1)"
check_contains "--check reports up to date" "up to date (9.9.9)" "$out"
OPT_CHECK=0; OPT_YES=0; OPT_SOURCE=""
unset -f update_selftest
INSTALL_DIR="$WORK"

# ------------------------------------------------------------------ result --

echo ""
echo "passed: $PASS   failed: $FAIL"
[ "$FAIL" -eq 0 ]
