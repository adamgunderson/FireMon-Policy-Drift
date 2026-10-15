#!/bin/bash
# HELP-START
# setup.sh -- configure and schedule the FireMon policy drift report.
#
# Usage:
#   bash setup.sh [VERB] [OPTIONS]
#
# Verbs:
#   menu               a pointer-driven menu of everything below. This is what
#                      runs when no verb is given -- the front door. Falls back
#                      to a numbered prompt on a terminal that cannot do ANSI.
#   install            the wizard: ask for settings, write config.ini and
#                      secrets.env, prove them with a dry run, then offer to
#                      schedule.
#   configure          write config.ini and secrets.env only; no scheduling.
#   verify             re-run the read-only checks against the live config:
#                      unit tests, device and policy lookup, a dry-run
#                      comparison rendered to out/. Sends nothing.
#   run                compare NOW and email the real recipients (a one-off,
#                      off-schedule run). --send-test ADDR redirects the
#                      message to ADDR instead. Prompts before sending.
#   schedule           install or replace the cron entry.
#   unschedule         remove the cron entry. Leaves every file alone.
#   status             report what is configured, scheduled and last found.
#   pairs              a sub-menu for the verbs below.
#   list-pairs         every pair: devices, policies, recipients, send rule.
#   add-pair           add ONE firewall pair to an existing config.ini -- the
#                      two devices, how rules are matched, which policies and
#                      rules, who gets its report and when -- without redoing
#                      the wizard. Lists devices and policies to pick from.
#   edit-pair [NAME]   change a pair: every prompt defaults to its current
#                      value, so Enter keeps it. Name as argument, --pair, or
#                      asked.
#   remove-pair [NAME] drop a pair and its last-run state. Past reports in
#                      out/ are kept.
#   add-recipient      add an email address (e.g. a manager who wants
#                      visibility) to one, several, or every pair's
#                      recipient list -- without redoing the wizard. Takes
#                      the address as an argument, or asks:
#                        bash setup.sh add-recipient boss@example.com
#                        bash setup.sh add-recipient boss@example.com --pair us-dr
#   restore-crontab    put back a crontab from backups/.
#   update             replace the program files with the newest release,
#                      keeping config.ini, secrets.env, state/, out/, the
#                      logs and the crontab. From GitHub by default; from a
#                      git clone with git pull; or from a tarball, zip or
#                      directory already on the box with --source. The files
#                      it replaces go to backups/ first, the unit tests run
#                      on the result, and a failure rolls back. --check only
#                      says whether a newer version exists.
#   uninstall          remove the cron entry, then optionally the config files.
#   help               this text.
#
# Options:
#   --dir DIR          install directory (default: the directory holding this
#                      script). Relative paths in config.ini resolve against it.
#   --at "M H D M W"   cron schedule (default: "0 6 * * *", daily at 06:00).
#   --live             schedule a real send. Without it the installed cron line
#                      carries --dry-run, which is the right first week.
#   --mail-proven      confirm that mail has been shown to leave this box.
#                      schedule --live refuses without it. --yes does NOT
#                      imply it: nobody should schedule real mail by habit.
#   --no-logrotate     do NOT install the monthly log-trimming cron lines
#                      (they are installed by default: they cap cron.log and
#                      delete out/ files older than 90 days).
#   --send-test ADDR   for `verify` and `run`: send the report to ADDR (with
#                      the real recipients stamped into the subject) instead
#                      of mailing the real recipients.
#   --pair NAME        for `add-recipient`: which pair to add to (repeatable).
#                      Without it, add-recipient asks (default: every pair).
#                      For `edit-pair` / `remove-pair`: the pair to act on.
#   --source PATH|URL  for `update`: where the new files come from -- a
#                      directory, a .tar.gz or .zip on this box, or a URL.
#                      Default: the GitHub tarball (see FMDRIFT_UPDATE_REPO).
#   --check            for `update`: report whether an update is available
#                      and change nothing.
#   --adopt            adopt an unmanaged drift cron line found in the crontab
#                      instead of stopping to ask about it.
#   --yes              accept the write confirmation without asking. Never
#                      skips a refusal, and never implies --mail-proven.
#
# Environment (each answers the matching prompt, for an unattended run):
#   FMDRIFT_PASSWORD        FireMon service account password (also read by
#                           the report itself; never written to config.ini)
#   FMDRIFT_SMTP_PASSWORD   SMTP password, if the relay needs one
#   FMDRIFT_SETUP_BASE_URL / _DOMAIN_ID / _USERNAME / _VERIFY_TLS
#   FMDRIFT_SETUP_DEVICE_FILTER   name fragment for the device listing
#   FMDRIFT_SETUP_KEEP_PAIRS      yes/no: keep the pairs already in config.ini
#   FMDRIFT_SETUP_PAIR_COUNT      how many NEW pairs to add (default: ask)
#   FMDRIFT_SETUP_LIST_PROPERTIES yes/no: survey properties for each pair
#   FMDRIFT_SETUP_PAIR<N>_NAME            e.g. FMDRIFT_SETUP_PAIR1_NAME=us-dr
#   FMDRIFT_SETUP_PAIR<N>_PRIMARY / _SECONDARY   device names (or ids)
#   FMDRIFT_SETUP_PAIR<N>_POLICIES        "all", or "A=B, C=D" policy pairs
#   FMDRIFT_SETUP_PAIR<N>_MATCH_BY        name | vendor_id (vendor_id for an HA pair
#                                         or two devices sharing one policy)
#   FMDRIFT_SETUP_PAIR<N>_CATEGORIES      "all", or comma-separated globs
#   FMDRIFT_SETUP_PAIR<N>_CHANGE_REQUESTS "none", or comma-separated CR numbers
#   FMDRIFT_SETUP_PAIR<N>_APPLICATIONS    "none", or comma-separated globs
#   FMDRIFT_SETUP_PAIR<N>_RECIPIENTS      "none", or comma-separated addresses
#   FMDRIFT_SETUP_PAIR<N>_SEND_WHEN       drift | always | changes
#   FMDRIFT_SETUP_SMTP_HOST / _SMTP_PORT / _SMTP_STARTTLS / _SMTP_USERNAME
#   FMDRIFT_SETUP_FROM_ADDRESS
#   FMDRIFT_SETUP_TARGET_PAIR       edit-pair / remove-pair: the pair, when not given
#                                   as an argument. add-pair and edit-pair read
#                                   FMDRIFT_SETUP_PAIR1_* for their answers.
#   FMDRIFT_SETUP_NEW_RECIPIENT     add-recipient: email(s) to add, comma-separated
#   FMDRIFT_SETUP_RECIPIENT_PAIRS   add-recipient: pair names, comma-separated, or "all"
#   FMDRIFT_UPDATE_REPO             update: GitHub repo (default adamgunderson/FireMon-Policy-Drift)
#   FMDRIFT_UPDATE_REF              update: branch or tag to fetch (default main)
#   FMDRIFT_UPDATE_SOURCE           update: same as --source
#
# What it writes, all inside the install directory:
#   config.ini      a copy of config.example.ini with your values patched in,
#                   comments and all. Never generated from scratch.
#   secrets.env     mode 0600, holds the passwords. Sourced by the cron line.
#   backups/        every crontab it replaces, and every config it overwrites.
#   setup.log       what this script did, and when.
#
# It does not need root, does not write outside the install directory apart
# from your own crontab, and never modifies postfix.
#
# Notes:
#   * It never claims mail was delivered. The relay accepting a message is the
#     last thing any SMTP client can observe -- run mailq yourself.
#   * The report exits 3 when it finds drift. That is a result, not a failure,
#     and the wizard treats it as one.
#   * On FMOS /usr/bin/python3 may be 3.6. Nothing here cares: run_drift.py
#     re-executes itself under a newer interpreter, so the installed cron line
#     names plain /usr/bin/python3 and keeps working across upgrades.
# HELP-END

# Not `set -e`: the healthy path here includes commands that are EXPECTED to
# fail -- grep finding no marker, crontab -l on a user who has none, the report
# exiting 3 because there is drift. Each is checked explicitly at its call
# site. `set -e` would turn the normal case into a silent abort.
set -uo pipefail

# config.ini and secrets.env are created here; creating them 0600 from the
# start beats creating them world-readable and chmod-ing afterwards.
umask 077

SCRIPT_PATH="$(readlink -f "$0" 2>/dev/null || echo "$0")"
INSTALL_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"

VERB=""
CRON_SPEC="0 6 * * *"
OPT_LIVE=0
OPT_MAIL_PROVEN=0
OPT_LOGROTATE=1
OPT_ADOPT=0
OPT_YES=0
OPT_SEND_TEST=""
OPT_SOURCE="${FMDRIFT_UPDATE_SOURCE:-}"
OPT_CHECK=0
VERB_FLAGS=()
PAIRS=()
# The one positional argument a verb takes, when it takes one: the crontab
# backup path for restore-crontab, the email address for add-recipient.
POSITIONAL_ARG=""

MARK_OPEN="# >>> firemon-drift managed block -- setup.sh >>>"
MARK_CLOSE="# <<< firemon-drift managed block -- setup.sh <<<"
TRIM_OPEN="# >>> firemon-drift log trimming -- setup.sh >>>"
TRIM_CLOSE="# <<< firemon-drift log trimming -- setup.sh <<<"

EXIT_OK=0
EXIT_FAIL=1
EXIT_CRON=2

# ---------------------------------------------------------------- output ----

usage() {
    sed -n '/^# HELP-START/,/^# HELP-END/p' "$SCRIPT_PATH" \
        | sed -e '1d' -e '$d' -e 's/^#\{1,\} \{0,1\}//'
}

# Every line the operator sees goes through here and lands in setup.log.
say() {
    local line="$1"
    printf '%s\n' "$line"
    printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$line" \
        >> "$INSTALL_DIR/setup.log" 2>/dev/null
}

ok()      { say "OK:      $1"; }
info()    { say "         $1"; }
action()  { say "ACTION:  $1"; }
warn()    { say "WARNING: $1"; }
skip()    { say "SKIP:    $1"; }
head2()   { say ""; say "=== $1 ==="; }

# To stderr: for functions whose stdout is their return value.
say_err() {
    printf '%s\n' "$1" >&2
    printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" \
        >> "$INSTALL_DIR/setup.log" 2>/dev/null
}

die() {
    say "ERROR:   $1"
    exit "${2:-$EXIT_FAIL}"
}

# A fatal error that must abort the WHOLE script even from inside a
# $(command substitution), where a plain `exit` only ends the subshell. The
# signal carries the exit code: TERM for a crontab problem (2), USR1 for a
# usage problem (1).
trap 'exit $EXIT_CRON' TERM
trap 'exit $EXIT_FAIL' USR1
fatal() {
    local sig="${2:-TERM}" code=$EXIT_CRON
    [ "$sig" = "USR1" ] && code=$EXIT_FAIL
    say_err "ERROR:   $1"
    if [ "${FMDRIFT_SETUP_LIB-}" != "1" ]; then
        kill -"$sig" "$$" 2>/dev/null
    fi
    exit "$code"
}

# ---------------------------------------------------------------- prompts ---

require_tty() {
    local question="$1" envvar="${2:-}"
    if { true < /dev/tty; } 2>/dev/null; then
        return 0
    fi
    local hint="Run this from an interactive shell."
    [ -n "$envvar" ] && hint="Set $envvar to answer it without a prompt."
    fatal "need to ask '$question' but there is no terminal to ask on. $hint 'bash setup.sh help' lists every variable the wizard reads." USR1
}

# Ask, with a default, honouring an environment override. An empty answer
# takes the default; a default of "" re-asks until something is typed.
ask() {
    local prompt="$1" default="$2" envvar="${3:-}" answer=""
    if [ -n "$envvar" ]; then
        local override="${!envvar-}"
        if [ -n "$override" ]; then
            printf '%s [%s]\n' "$prompt" "$override" >&2
            printf '%s' "$override"
            return 0
        fi
    fi
    require_tty "$prompt" "$envvar"
    while true; do
        if [ -n "$default" ]; then
            read -r -p "$prompt [$default]: " answer < /dev/tty
            answer="${answer:-$default}"
        else
            read -r -p "$prompt: " answer < /dev/tty
        fi
        [ -n "$answer" ] && break
        printf 'A value is required.\n' >&2
    done
    printf '%s' "$answer"
}

ask_secret() {
    local prompt="$1" envvar="$2" first="" second=""
    local override="${!envvar-}"
    if [ -n "$override" ]; then
        printf '%s [taken from %s]\n' "$prompt" "$envvar" >&2
        printf '%s' "$override"
        return 0
    fi
    require_tty "$prompt" "$envvar"
    while true; do
        read -r -s -p "$prompt: " first < /dev/tty; printf '\n' >&2
        read -r -s -p "Confirm: " second < /dev/tty; printf '\n' >&2
        [ "$first" = "$second" ] && [ -n "$first" ] && break
        printf 'Did not match, or was empty. Again.\n' >&2
    done
    printf '%s' "$first"
}

confirm() {
    local prompt="$1" answer=""
    if [ "$OPT_YES" -eq 1 ]; then
        info "$prompt -- yes (--yes)"
        return 0
    fi
    require_tty "$prompt" "(or pass --yes)"
    read -r -p "$prompt [y/N]: " answer < /dev/tty
    case "$answer" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

# ------------------------------------------------------------- validation ---

# configparser reads ' ;' and ' #' as the start of an inline comment and would
# silently truncate the value. Refused at the prompt instead.
reject_unsafe() {
    local what="$1" value="$2"
    case "$value" in
        *" ;"*) die "$what may not contain ' ;' -- config.ini would treat the rest as a comment." ;;
        *" #"*) die "$what may not contain ' #' -- config.ini would treat the rest as a comment." ;;
    esac
    case "$value" in
        *$'\n'*|*$'\r'*) die "$what may not contain a line break." ;;
    esac
}

need_int() {
    local what="$1" value="$2"
    case "$value" in
        ''|*[!0-9]*) die "$what must be a whole number (got '$value')." ;;
    esac
}

yesno_to_bool() {
    case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
        y|yes|true|1|on)  printf 'true' ;;
        n|no|false|0|off) printf 'false' ;;
        *) die "expected yes or no, got '$1'." ;;
    esac
}

# Validate a comma-separated list of email addresses and echo it back
# normalised. Aborts via fatal(): always called as var="$(...)".
_parse_email_list() {
    local raw="$1" label="$2" out='' item
    local IFS=','
    for item in $raw; do
        item="$(printf '%s' "$item" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
        [ -z "$item" ] && continue
        case "$item" in
            *";"*|*"#"*)
                fatal "$label '$item' contains a character config.ini cannot store (; or #)." USR1 ;;
        esac
        case "$item" in
            *@*.*) ;;
            *) fatal "$label '$item' is not an email address." USR1 ;;
        esac
        out="${out:+$out,}$item"
    done
    [ -n "$out" ] || fatal "no valid $label was given." USR1
    printf '%s' "$out"
}

# A comma-separated list of plain values (categories, CR numbers...) trimmed
# and re-joined. Only the characters config.ini cannot hold are refused.
_parse_plain_list() {
    local raw="$1" label="$2" out='' item
    local IFS=','
    for item in $raw; do
        item="$(printf '%s' "$item" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
        [ -z "$item" ] && continue
        case "$item" in
            *";"*|*"#"*|*"="*)
                fatal "$label '$item' contains a character config.ini cannot store here (; # =)." USR1 ;;
        esac
        out="${out:+$out, }$item"
    done
    [ -n "$out" ] || fatal "no valid $label was given." USR1
    printf '%s' "$out"
}

# "A=B, C" -> lines "A = B" and "C = C" for the [policies] section, written to
# the file named in $3. Echoes a one-line summary.
_parse_policy_pairs() {
    local raw="$1" label="$2" file="$3" item a b out=''
    : > "$file"
    local IFS=','
    for item in $raw; do
        item="$(printf '%s' "$item" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
        [ -z "$item" ] && continue
        a="${item%%=*}"; b="${item#*=}"
        [ "$a" = "$item" ] && b="$a"
        a="$(printf '%s' "$a" | sed 's/[[:space:]]*$//')"
        b="$(printf '%s' "$b" | sed 's/^[[:space:]]*//')"
        case "$a$b" in
            *";"*|*"#"*|*"["*|*"]"*)
                fatal "$label '$item' contains a character config.ini cannot store here (; # [ ])." USR1 ;;
        esac
        [ -n "$a" ] && [ -n "$b" ] || fatal "$label '$item' is not 'primary policy = secondary policy'." USR1
        printf '%s = %s\n' "$a" "$b" >> "$file"
        out="${out:+$out; }$a -> $b"
    done
    [ -n "$out" ] || fatal "no valid $label was given." USR1
    printf '%s' "$out"
}

# ---------------------------------------------------------- config patching -

# Rewrite named keys inside a copy of config.example.ini, keeping every
# comment. Every key must match EXACTLY ONCE, or nothing is written.
patch_config() {
    local target="$1" table="$2" stderr_file
    stderr_file="$(mktemp)"

    awk -v TABLE="$table" '
        BEGIN {
            while ((getline entry < TABLE) > 0) {
                bar1 = index(entry, "|")
                rest = substr(entry, bar1 + 1)
                bar2 = index(rest, "|")
                if (bar1 == 0 || bar2 == 0) continue
                sec = substr(entry, 1, bar1 - 1)
                key = substr(rest, 1, bar2 - 1)
                want[sec "|" key] = substr(rest, bar2 + 1)
                hits[sec "|" key] = 0
            }
            close(TABLE)
            section = ""
        }
        /^[[:space:]]*\[/ {
            s = $0
            sub(/^[[:space:]]*\[/, "", s)
            sub(/\].*$/, "", s)
            section = s
            print
            next
        }
        {
            if (match($0, /^[[:space:]]*[A-Za-z0-9_]+[[:space:]]*=/)) {
                head = substr($0, RSTART, RLENGTH)
                key = head
                sub(/[[:space:]]*=$/, "", key)
                sub(/^[[:space:]]+/, "", key)
                id = section "|" key
                if (id in want) {
                    hits[id]++
                    # No trailing space after '=' for an empty value.
                    if (want[id] == "") print head; else print head " " want[id]
                    next
                }
            }
            print
        }
        END {
            failed = 0
            for (id in want) {
                if (hits[id] != 1) {
                    printf("%s matched %d times\n", id, hits[id]) > "/dev/stderr"
                    failed = 1
                }
            }
            if (failed) exit 3
        }
    ' "$target" > "$target.patched" 2>"$stderr_file"
    local rc=$?

    if [ "$rc" -ne 0 ]; then
        say "ERROR:   could not patch $(basename "$target") -- config.example.ini"
        say "         does not have the keys this script expects:"
        while IFS= read -r line; do say "           $line"; done < "$stderr_file"
        say "         Nothing was written. Edit config.ini by hand from"
        say "         config.example.ini, or update setup.sh to match."
        rm -f "$stderr_file" "$target.patched"
        exit "$EXIT_FAIL"
    fi
    rm -f "$stderr_file"
    mv "$target.patched" "$target"
}

table_add() {
    printf '%s|%s|%s\n' "$1" "$2" "$3" >> "$TABLE_FILE"
}

# Replace the live entries of one section with the lines in a file, keeping
# the section's comments. For [policies], whose keys are policy NAMES and so
# cannot be patched by key like the other settings. Existing live keys are
# dropped; the new lines land after the section's comments.
set_section_entries() {
    local target="$1" section="$2" entries="$3"
    awk -v SEC="$section" -v ENTRIES="$entries" '
        function flush() {
            if (inside && !done) {
                while ((getline line < ENTRIES) > 0) print line
                close(ENTRIES)
                done = 1
            }
        }
        /^[[:space:]]*\[/ {
            flush()
            s = $0; sub(/^[[:space:]]*\[/, "", s); sub(/\].*$/, "", s)
            inside = (s == SEC)
            print
            next
        }
        {
            if (inside) {
                if ($0 ~ /^[[:space:]]*[^;#[:space:]][^=]*=/) next
                if ($0 ~ /^[[:space:]]*$/) { flush(); print; next }
            }
            print
        }
        END { flush() }
    ' "$target" > "$target.patched" || die "could not rewrite [$section] in $(basename "$target")"
    mv "$target.patched" "$target"
}

# ---- pair sections ---------------------------------------------------------
#
# Pairs live in [pair:NAME] sections (plus optional [policies:NAME],
# [property_filters:NAME] and [normalise:NAME]). The wizard appends new ones
# and, on a re-run, can carry the existing ones across unchanged.

# Every pair-scoped section of a config file, verbatim, in file order.
extract_pair_sections() {
    awk '
        /^[[:space:]]*\[/ {
            s = $0; sub(/^[[:space:]]*\[/, "", s); sub(/\].*$/, "", s)
            keep = (tolower(s) ~ /^(pair|policies|property_filters|normalise):/)
        }
        keep { print }
    ' "$1"
}

# The NAME of every [pair:NAME] section, one per line.
list_pair_names() {
    awk '
        /^[[:space:]]*\[[Pp][Aa][Ii][Rr]:/ {
            s = $0; sub(/^[[:space:]]*\[[Pp][Aa][Ii][Rr]:/, "", s); sub(/\].*$/, "", s)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", s)
            print s
        }
    ' "$1"
}

# Write one [pair:NAME] section to the end of a file. Every key is written
# explicitly ("all" / "none" where empty) so the operator can see what the
# pair does without knowing the inheritance rules.
append_pair_section() {
    local file="$1" name="$2" primary="$3" secondary="$4" policies="$5" \
          categories="$6" change_requests="$7" applications="$8" \
          recipients="$9" send_when="${10}" match_by="${11:-name}"
    {
        printf '\n[pair:%s]\n' "$name"
        printf 'primary         = %s\n' "$primary"
        printf 'secondary       = %s\n' "$secondary"
        printf 'policies        = %s\n' "${policies:-all}"
        printf 'match_by        = %s\n' "$match_by"
        printf 'categories      = %s\n' "${categories:-all}"
        printf 'change_requests = %s\n' "${change_requests:-none}"
        printf 'applications    = %s\n' "${applications:-none}"
        printf 'recipients      = %s\n' "${recipients:-none}"
        printf 'send_when       = %s\n' "$send_when"
    } >> "$file"
}


# Set one "key = value" line in a section: replace the live line if the
# section has it, else add it after the section's last live line. For
# editing a pair whose section may lack some keys (written by hand, or by an
# older version of the wizard).
set_section_key() {
    local target="$1" section="$2" key="$3" value="$4"
    awk -v SEC="$section" -v KEY="$key" -v VAL="$value" '
        function emit() { if (VAL == "") printf("%-15s =\n", KEY); else printf("%-15s = %s\n", KEY, VAL) }
        function flush_blanks() { while (blanks > 0) { print ""; blanks-- } }
        /^[[:space:]]*\[/ {
            if (inside && !done) { emit(); done = 1 }
            flush_blanks()
            s = $0; sub(/^[[:space:]]*\[/, "", s); sub(/\].*$/, "", s)
            inside = (s == SEC); print; next
        }
        {
            if (inside) {
                if ($0 ~ /^[[:space:]]*$/) { blanks++; next }
                if (!done && match($0, /^[[:space:]]*[A-Za-z0-9_]+[[:space:]]*=/)) {
                    k = substr($0, RSTART, RLENGTH); sub(/[[:space:]]*=$/, "", k); sub(/^[[:space:]]+/, "", k)
                    if (k == KEY) { flush_blanks(); emit(); done = 1; next }
                }
            }
            flush_blanks(); print
        }
        END { if (inside && !done) emit(); flush_blanks() }
    ' "$target" > "$target.patched" || die "could not set $key in [$section] of $(basename "$target")"
    mv "$target.patched" "$target"
}

# Drop a [pair:NAME] section and the [policies:NAME], [property_filters:NAME]
# and [normalise:NAME] sections scoped to it. Case-insensitive on the name.
remove_pair_sections() {
    local target="$1" name="$2"
    awk -v want="$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')" '
        /^[[:space:]]*\[/ {
            s = $0; sub(/^[[:space:]]*\[/, "", s); sub(/\].*$/, "", s)
            drop = 0
            if (tolower(s) ~ /^(pair|policies|property_filters|normalise):/) {
                n = s; sub(/^[^:]*:[[:space:]]*/, "", n)
                if (tolower(n) == want) drop = 1
            }
            if (drop) next
            print; next
        }
        { if (!drop) print }
    ' "$target" > "$target.patched" || die "could not remove pair '$name' from $(basename "$target")"
    mv "$target.patched" "$target"
}

# The state file a pair keeps (NEW/resolved markers), by the same slug rule
# as firemon_drift/state.py.
pair_state_file() {
    local slug
    slug="$(printf '%s' "$1" | sed 's/[^A-Za-z0-9._-]\{1,\}/_/g; s/^_//; s/_$//')"
    printf '%s/state/last-%s.json' "$INSTALL_DIR" "${slug:-x}"
}

# Insert the contents of a file into a config just before the named section
# header, so appended pair sections sit beside [pair] rather than at the end.
insert_before_section() {
    local target="$1" section="$2" insert="$3"
    awk -v SEC="$section" -v INSERT="$insert" '
        /^[[:space:]]*\[/ && !done {
            s = $0; sub(/^[[:space:]]*\[/, "", s); sub(/\].*$/, "", s)
            if (s == SEC) {
                while ((getline line < INSERT) > 0) print line
                close(INSERT)
                print ""
                done = 1
            }
        }
        { print }
        END { if (!done) { while ((getline line < INSERT) > 0) print line; close(INSERT) } }
    ' "$target" > "$target.patched" || die "could not insert into $(basename "$target")"
    mv "$target.patched" "$target"
}

# One line per configured pair, for `status` and the preview:
#   NAME: PRIMARY -> SECONDARY | policies ... | recipients ... | send_when
pair_summary_lines() {
    awk '
        function flush() {
            if (name != "" && (primary != "" || secondary != "")) {
                printf("%s: %s -> %s | policies %s | %s | send_when %s\n",
                       name, primary, secondary,
                       (policies == "" ? "(global)" : policies),
                       (recipients == "" ? "recipients (global)" : "to " recipients),
                       (send_when == "" ? "(global)" : send_when))
            }
            name = ""; primary = ""; secondary = ""; policies = ""; recipients = ""; send_when = ""
        }
        function val(line,   v) { v = line; sub(/^[^=]*=[[:space:]]*/, "", v); sub(/[[:space:]]+$/, "", v); return v }
        /^[[:space:]]*\[/ {
            flush()
            s = $0; sub(/^[[:space:]]*\[/, "", s); sub(/\].*$/, "", s)
            if (tolower(s) == "pair") name = "default"
            else if (tolower(s) ~ /^pair:/) { name = s; sub(/^[^:]*:[[:space:]]*/, "", name) }
            next
        }
        name != "" && /^[[:space:]]*primary[[:space:]]*=/    { primary = val($0) }
        name != "" && /^[[:space:]]*secondary[[:space:]]*=/  { secondary = val($0) }
        name != "" && /^[[:space:]]*policies[[:space:]]*=/   { policies = val($0) }
        name != "" && /^[[:space:]]*recipients[[:space:]]*=/ { recipients = val($0) }
        name != "" && /^[[:space:]]*send_when[[:space:]]*=/  { send_when = val($0) }
        END { flush() }
    ' "$1"
}

# The name of every configured pair, one per line: "default" for a bare
# [pair] section with a primary set, plus every [pair:NAME].
list_all_pair_names() {
    local file="$1"
    if [ -n "$(config_value "$file" pair primary)" ]; then
        printf 'default\n'
    fi
    list_pair_names "$file"
}

# The exact "[...]" section text (without brackets) for a pair name, matched
# case-insensitively against what is actually in the file -- needed because
# patch_config compares section names literally. Empty if no such pair.
find_pair_section() {
    local file="$1" name="$2"
    if [ "$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')" = "default" ]; then
        [ -n "$(config_value "$file" pair primary)" ] && printf 'pair'
        return 0
    fi
    awk -v want="$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')" '
        /^[[:space:]]*\[[Pp][Aa][Ii][Rr]:/ {
            s = $0; sub(/^[[:space:]]*\[/, "", s); sub(/\].*$/, "", s)
            n = s; sub(/^[^:]*:[[:space:]]*/, "", n)
            if (tolower(n) == want) { print s; exit }
        }
    ' "$file"
}

# Merge a comma-separated list of new addresses into a pair's current
# `recipients` value ("none", empty, or a comma list), deduping
# case-insensitively (including a pre-existing duplicate within `current`
# itself) while keeping the original casing and order, and adding genuinely
# new addresses at the end.
#
# Sets two globals rather than returning through stdout: MERGE_RESULT (the
# merged list) and MERGE_ADDED_COUNT (how many addresses were actually new,
# so the caller can skip a pair that already has everyone). Call it as a
# plain statement, NOT as `x=$(merge_recipients ...)` -- command
# substitution runs the function in a subshell, and a subshell's variable
# assignments never reach the caller, so MERGE_ADDED_COUNT would silently
# stay at whatever it was before the call.
MERGE_RESULT=""
MERGE_ADDED_COUNT=0
merge_recipients() {
    local current="$1" additions="$2" out='' seen item lower
    seen="$(mktemp)"
    MERGE_ADDED_COUNT=0
    if [ -n "$current" ] && [ "$(printf '%s' "$current" | tr '[:upper:]' '[:lower:]')" != "none" ]; then
        local IFS=','
        for item in $current; do
            item="$(printf '%s' "$item" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
            [ -z "$item" ] && continue
            lower="$(printf '%s' "$item" | tr '[:upper:]' '[:lower:]')"
            grep -qxF "$lower" "$seen" 2>/dev/null && continue
            printf '%s\n' "$lower" >> "$seen"
            out="${out:+$out, }$item"
        done
    fi
    local IFS=','
    for item in $additions; do
        item="$(printf '%s' "$item" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
        [ -z "$item" ] && continue
        lower="$(printf '%s' "$item" | tr '[:upper:]' '[:lower:]')"
        grep -qxF "$lower" "$seen" 2>/dev/null && continue
        printf '%s\n' "$lower" >> "$seen"
        out="${out:+$out, }$item"
        MERGE_ADDED_COUNT=$((MERGE_ADDED_COUNT + 1))
    done
    rm -f "$seen"
    MERGE_RESULT="$out"
}

# Read one value back out of a config file, for `status`.
config_value() {
    local file="$1" section="$2" key="$3"
    [ -f "$file" ] || { printf '(no config)'; return; }
    awk -v sec="$section" -v key="$key" '
        /^[[:space:]]*\[/ { s = $0; sub(/^[[:space:]]*\[/, "", s); sub(/\].*$/, "", s); cur = s; next }
        {
            if (cur != sec) next
            if (match($0, /^[[:space:]]*[A-Za-z0-9_]+[[:space:]]*=/)) {
                k = substr($0, RSTART, RLENGTH); sub(/[[:space:]]*=$/, "", k); sub(/^[[:space:]]+/, "", k)
                if (k == key) { v = substr($0, RSTART + RLENGTH); sub(/^[[:space:]]+/, "", v); print v; exit }
            }
        }
    ' "$file"
}

# Every live "key = value" line of a section, for `status` on [policies].
config_section_lines() {
    local file="$1" section="$2"
    [ -f "$file" ] || return 0
    awk -v sec="$section" '
        /^[[:space:]]*\[/ { s = $0; sub(/^[[:space:]]*\[/, "", s); sub(/\].*$/, "", s); cur = s; next }
        { if (cur == sec && $0 ~ /^[[:space:]]*[^;#[:space:]][^=]*=/) print }
    ' "$file"
}

# --------------------------------------------------------------- crontab ----

have() { command -v "$1" >/dev/null 2>&1; }

mail_queue_count() {
    have mailq || { printf '?'; return; }
    local out
    out="$(mailq 2>/dev/null)"
    if printf '%s' "$out" | grep -qi 'mail queue is empty'; then
        printf '0'; return
    fi
    local n
    n="$(printf '%s\n' "$out" | sed -n 's/.*in \([0-9][0-9]*\) Request.*/\1/p' | tail -n 1)"
    if [ -n "$n" ]; then printf '%s' "$n"; return; fi
    printf '%s\n' "$out" | grep -c '^[A-Za-z0-9]\{5,\}[*!]\?[[:space:]]'
}

# Read the crontab, distinguishing "this user has none" from "could not read".
crontab_read() {
    local out err rc
    err="$(mktemp)"
    out="$(crontab -l 2>"$err")"
    rc=$?
    if [ "$rc" -eq 0 ]; then
        rm -f "$err"
        printf '%s\n' "$out"
        return 0
    fi
    if grep -qi 'no crontab for' "$err"; then
        rm -f "$err"
        return 0
    fi
    local detail
    detail="$(cat "$err")"
    rm -f "$err"
    fatal "could not read the crontab, and the reason is not 'no crontab for $(id -un)'. Refusing to write one. crontab -l said: $detail"
}

LAST_BACKUP=""
crontab_backup() {
    local content="$1" stamp path expected actual
    stamp="$(date '+%Y%m%dT%H%M%S')"
    path="$INSTALL_DIR/backups/crontab-$stamp.bak"
    mkdir -p "$INSTALL_DIR/backups" || die "could not create $INSTALL_DIR/backups"
    printf '%s\n' "$content" > "$path" || die "could not write $path"
    expected="$(printf '%s\n' "$content" | wc -c)"
    actual="$(wc -c < "$path")"
    if [ "$expected" -ne "$actual" ]; then
        die "backup $path is $actual bytes but should be $expected -- refusing to touch the crontab."
    fi
    ok "crontab backed up: $path"
    info "restore it with:  crontab $path"
    ls -1t "$INSTALL_DIR/backups"/crontab-*.bak 2>/dev/null | tail -n +11 \
        | while IFS= read -r old; do rm -f "$old"; done
    LAST_BACKUP="$path"
}

strip_block() {
    local content="$1" open="$2" close="$3" opens closes
    opens="$(printf '%s\n' "$content" | grep -cxF "$open")"
    closes="$(printf '%s\n' "$content" | grep -cxF "$close")"
    if [ "$opens" != "$closes" ] || [ "$opens" -gt 1 ]; then
        fatal "the crontab has $opens opening and $closes closing firemon-drift markers. That is not something this script can safely rewrite. Edit it by hand with: crontab -e"
    fi
    printf '%s\n' "$content" | awk -v mark_open="$open" -v mark_close="$close" '
        $0 == mark_open  { inside = 1; next }
        $0 == mark_close { inside = 0; next }
        !inside { print }
    '
}

trailing_mailto() {
    printf '%s\n' "$1" | grep -E '^[[:space:]]*MAILTO[[:space:]]*=' | tail -n 1
}

drift_cron_line() {
    local flags="$1" dir="$INSTALL_DIR"
    if [ "$dir" = "$HOME/firemon-drift" ]; then
        dir='$HOME/firemon-drift'
    fi
    printf '%s . "%s/secrets.env"; /usr/bin/python3 "%s/run_drift.py" --config "%s/config.ini"%s >> "%s/cron.log" 2>&1' \
        "$CRON_SPEC" "$dir" "$dir" "$dir" "$flags" "$dir"
}

build_managed_block() {
    local flags="$1" prior_mailto="$2" block

    block="$MARK_OPEN
# FireMon policy drift report. Rewritten by setup.sh; do not edit here.
# MAILTO is emptied so cron does not mail this output every run -- errors
# still land in cron.log. Exit 3 means drift was found, not a failure.
MAILTO=\"\"
$(drift_cron_line "$flags")"

    if [ "$OPT_LOGROTATE" -eq 1 ]; then
        block="$block
$TRIM_OPEN
# Keep the log and out/ from growing without bound.
0 3 1 * * tail -n 2000 \"$INSTALL_DIR/cron.log\" > \"$INSTALL_DIR/cron.log.tmp\" && mv \"$INSTALL_DIR/cron.log.tmp\" \"$INSTALL_DIR/cron.log\"
0 3 1 * * find \"$INSTALL_DIR/out\" -type f -mtime +90 -delete
$TRIM_CLOSE"
    fi

    if [ -n "$prior_mailto" ]; then
        block="$block
# Restoring the MAILTO that was in force before this block, so anything added
# below it does not silently inherit MAILTO=\"\".
$prior_mailto"
    else
        block="$block
# NOTE: MAILTO=\"\" above applies to every line below it too. If you add a job
# beneath this block and want cron to mail its output, set MAILTO first."
    fi

    printf '%s\n%s' "$block" "$MARK_CLOSE"
}

# Run the exact command we are about to install, in an approximation of cron's
# environment, with --dry-run forced. Exit 3 (drift) is a result, not a fault.
rehearse_cron() {
    local line rc
    line="$(drift_cron_line ' --dry-run')"
    line="${line#"$CRON_SPEC" }"
    info "rehearsing the installed command under a minimal environment..."
    env -i HOME="$HOME" PATH=/usr/bin:/bin LANG=C SHELL=/bin/sh \
        /bin/sh -c "$line" >/dev/null 2>"$INSTALL_DIR/.rehearsal.err"
    rc=$?
    if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then
        say "ERROR:   the command failed when run the way cron will run it"
        say "         (exit $rc). Nothing has been scheduled. It said:"
        if [ -s "$INSTALL_DIR/cron.log" ]; then
            while IFS= read -r l; do say "           $l"; done \
                < <(tail -n 15 "$INSTALL_DIR/cron.log")
        elif [ -s "$INSTALL_DIR/.rehearsal.err" ]; then
            while IFS= read -r l; do say "           $l"; done \
                < <(tail -n 15 "$INSTALL_DIR/.rehearsal.err")
        else
            say "           (no output anywhere -- run it yourself to see why:)"
            say "           $line"
        fi
        rm -f "$INSTALL_DIR/.rehearsal.err"
        exit "$EXIT_FAIL"
    fi
    rm -f "$INSTALL_DIR/.rehearsal.err"
    ok "the command runs correctly in a cron-like environment"
    info "this approximates cron's environment; it does not guarantee it"
}

crontab_write() {
    local content="$1" expect_marker="$2" tmp readback found
    tmp="$(mktemp)"
    printf '%s\n' "$content" | sed -e '/^$/{ $d }' > "$tmp"

    if ! crontab "$tmp" 2>/dev/null; then
        if ! crontab - < "$tmp"; then
            rm -f "$tmp"
            _crontab_restore "crontab refused the new content"
        fi
    fi
    rm -f "$tmp"

    readback="$(crontab_read)"
    if [ -n "$expect_marker" ]; then
        found="$(printf '%s\n' "$readback" | grep -cxF "$expect_marker")"
        [ "$found" -eq 1 ] || _crontab_restore "the managed block is not in the crontab after writing it"
    else
        found="$(printf '%s\n' "$readback" | grep -cxF "$MARK_OPEN")"
        [ "$found" -eq 0 ] || _crontab_restore "the managed block is still in the crontab after removing it"
    fi
}

_crontab_restore() {
    local why="$1"
    say_err "ERROR:   $why."
    if [ -n "$LAST_BACKUP" ] && [ -f "$LAST_BACKUP" ]; then
        if crontab "$LAST_BACKUP" 2>/dev/null; then
            say_err "         Restored the crontab from $LAST_BACKUP."
        else
            say_err "         COULD NOT auto-restore. Do it by hand: crontab $LAST_BACKUP"
        fi
    fi
    exit "$EXIT_CRON"
}

# ------------------------------------------------------------- preflight ----

preflight() {
    head2 "Environment"

    [ -w "$INSTALL_DIR" ] || die "$INSTALL_DIR is not writable."

    local missing=0 f
    for f in run_drift.py run_tests.py config.example.ini \
             templates/drift.html templates/drift.txt; do
        if [ ! -f "$INSTALL_DIR/$f" ]; then
            warn "missing: $f"
            missing=1
        fi
    done
    [ "$missing" -eq 0 ] || die "this does not look like a complete install."

    case "$INSTALL_DIR" in
        *"%"*|*";"*|*"#"*|*'"'*|*'$'*|*'`'*|*'\'*)
            die "the install path contains a character this installer cannot put safely in a cron line or config.ini (one of  % ; # \" \$ \` \\ ): $INSTALL_DIR" ;;
    esac
    case "$INSTALL_DIR" in
        *$'\n'*|*$'\r'*) die "the install path contains a line break." ;;
    esac

    ok "install directory: $INSTALL_DIR"
    if [ "$INSTALL_DIR" != "$HOME/firemon-drift" ]; then
        warn "not ~/firemon-drift -- the commands quoted in README.md and"
        warn "DEPLOYMENT.md name that path and will need adjusting."
    fi

    local py
    py="$(command -v python3 || true)"
    if [ -n "$py" ]; then
        ok "python3: $py ($("$py" -V 2>&1))"
        info "the report re-executes itself under a newer interpreter if this"
        info "one is too old, so 3.6 here is fine"
    else
        die "no python3 on PATH."
    fi

    if [ -n "${FMDRIFT_REEXEC-}" ]; then
        warn "FMDRIFT_REEXEC is set in this shell. It is the report's own"
        warn "exec-loop guard and will break a 3.6 start. Run: unset FMDRIFT_REEXEC"
    fi

    for tool in crontab mailq postconf; do
        if have "$tool"; then ok "$tool: present"; else info "$tool: not present"; fi
    done
    if have systemctl && systemctl is-active postfix >/dev/null 2>&1; then
        ok "postfix: active"
    else
        info "postfix: not active or not detectable -- you will need a relay"
    fi
}

# --------------------------------------------------------------- verbs ------

# Run the report against a candidate config with staged secrets.
_run_candidate() {
    local candidate="$1" secrets="$2"
    shift 2
    ( set -a; . "$secrets"; set +a
      python3 "$INSTALL_DIR/run_drift.py" --config "$candidate" "$@" )
}

do_configure() {
    rm -f "$INSTALL_DIR/config.ini.new" "$INSTALL_DIR/secrets.env.new"
    preflight
    head2 "FireMon"

    local base_url domain_id username password verify_tls
    base_url="$(ask 'FireMon base URL' 'https://localhost' FMDRIFT_SETUP_BASE_URL)"
    case "$base_url" in
        HTTP://*|HTTPS://*|Http://*|Https://*)
            base_url="$(printf '%s' "$base_url" | sed -e 's#^[Hh][Tt][Tt][Pp]\(s\{0,1\}\)://#http\1://#')" ;;
    esac
    case "$base_url" in
        http://*|https://*) ;;
        *) die "the base URL must start with http:// or https:// (got '$base_url')." ;;
    esac
    base_url="${base_url%/}"
    reject_unsafe "The base URL" "$base_url"

    domain_id="$(ask 'Domain id' '1' FMDRIFT_SETUP_DOMAIN_ID)"
    need_int "Domain id" "$domain_id"

    username="$(ask 'FireMon service account username' '' FMDRIFT_SETUP_USERNAME)"
    reject_unsafe "The username" "$username"
    password="$(ask_secret 'FireMon password' FMDRIFT_PASSWORD)"

    local tls_default='yes'
    case "$base_url" in *localhost*|*127.0.0.1*) tls_default='no' ;; esac
    verify_tls="$(ask 'Verify the TLS certificate? (the appliance certificate is self-signed)' "$tls_default" FMDRIFT_SETUP_VERIFY_TLS)"
    verify_tls="$(yesno_to_bool "$verify_tls")"

    # ---- build the candidate config with what we have so far -------------
    local candidate="$INSTALL_DIR/config.ini.new"
    cp -f "$INSTALL_DIR/config.example.ini" "$candidate" \
        || die "could not copy config.example.ini"

    TABLE_FILE="$(mktemp)"
    : > "$TABLE_FILE"
    table_add firemon base_url    "$base_url"
    table_add firemon domain_id   "$domain_id"
    table_add firemon auth_mode   "token"
    table_add firemon username    "$username"
    table_add firemon verify_tls  "$verify_tls"
    table_add paths   template_dir "$INSTALL_DIR/templates"
    table_add paths   output_dir   "$INSTALL_DIR/out"
    table_add paths   state_dir    "$INSTALL_DIR/state"
    table_add paths   log_file     "$INSTALL_DIR/drift.log"
    patch_config "$candidate" "$TABLE_FILE"
    rm -f "$TABLE_FILE"

    stage_secrets "$password" ""
    local staged_secrets="$INSTALL_DIR/secrets.env.new"

    # ---- pairs -----------------------------------------------------------
    head2 "Firewall pairs"
    info "a pair is two firewalls whose policies should match: the primary is"
    info "the reference, the secondary is expected to mirror it. Each pair has"
    info "its own recipients, its own filters and its own last-run state."
    local pairs_file kept=0
    pairs_file="$(mktemp)"; : > "$pairs_file"
    if [ -f "$INSTALL_DIR/config.ini" ] && [ -n "$(list_pair_names "$INSTALL_DIR/config.ini")" ]; then
        local existing_names keep
        existing_names="$(list_pair_names "$INSTALL_DIR/config.ini" | tr '\n' ' ')"
        keep="$(ask "Keep the pairs already configured ($existing_names)? (yes/no)" 'yes' FMDRIFT_SETUP_KEEP_PAIRS)"
        if [ "$(yesno_to_bool "$keep")" = "true" ]; then
            extract_pair_sections "$INSTALL_DIR/config.ini" >> "$pairs_file"
            kept="$(list_pair_names "$INSTALL_DIR/config.ini" | wc -l)"
            info "keeping $kept existing pair(s) unchanged"
        fi
    fi
    DEVICES_LISTED=0
    local n=0 more want_count="${FMDRIFT_SETUP_PAIR_COUNT-}"
    [ -z "$want_count" ] || need_int "FMDRIFT_SETUP_PAIR_COUNT" "$want_count"
    while true; do
        if [ -n "$want_count" ]; then
            [ "$n" -lt "$want_count" ] || break
        elif [ "$n" -gt 0 ] || [ "$kept" -gt 0 ]; then
            more="$(ask 'Add another pair? (yes/no)' 'no')"
            [ "$(yesno_to_bool "$more")" = "true" ] || break
        fi
        n=$((n + 1))
        _configure_pair "$n" "$candidate" "$staged_secrets" "$pairs_file"
    done
    if [ "$n" -eq 0 ] && [ "$kept" -eq 0 ]; then
        rm -f "$candidate" "$staged_secrets" "$pairs_file"
        die "at least one pair is needed. Nothing was written."
    fi
    insert_before_section "$candidate" compare "$pairs_file"
    rm -f "$pairs_file"

    head2 "Mail relay"
    local smtp_host smtp_port smtp_tls smtp_user smtp_pass from_address
    smtp_host="$(ask 'SMTP relay host' 'localhost' FMDRIFT_SETUP_SMTP_HOST)"
    reject_unsafe "The SMTP host" "$smtp_host"
    smtp_port='25'; smtp_tls='false'; smtp_user=''; smtp_pass=''
    if [ "$smtp_host" != "localhost" ] && [ "$smtp_host" != "127.0.0.1" ]; then
        smtp_port="$(ask 'SMTP port' '25' FMDRIFT_SETUP_SMTP_PORT)"
        need_int "SMTP port" "$smtp_port"
        smtp_tls="$(yesno_to_bool "$(ask 'Use STARTTLS?' 'yes' FMDRIFT_SETUP_SMTP_STARTTLS)")"
        smtp_user="$(ask 'SMTP username (blank if the relay does not authenticate)' 'none' FMDRIFT_SETUP_SMTP_USERNAME)"
        [ "$smtp_user" = "none" ] && smtp_user=""
        reject_unsafe "The SMTP username" "$smtp_user"
        if [ -n "$smtp_user" ]; then
            smtp_pass="$(ask_secret 'SMTP password' FMDRIFT_SMTP_PASSWORD)"
        fi
    else
        info "localhost relay: no port, STARTTLS or credentials to set"
    fi
    from_address="$(ask 'From address for the report' "firemon-drift@$(hostname -f 2>/dev/null || hostname)" FMDRIFT_SETUP_FROM_ADDRESS)"
    reject_unsafe "The from address" "$from_address"
    case "$from_address" in *@*.*) ;; *) die "'$from_address' is not a usable email address." ;; esac
    if have postconf; then
        local canon
        canon="$(postconf -h sender_canonical_maps 2>/dev/null || true)"
        if [ -n "$canon" ]; then
            warn "postfix rewrites senders via $canon -- the recipient may not"
            warn "see $from_address. Check /etc/postfix/sender_canonical."
        fi
    fi

    TABLE_FILE="$(mktemp)"; : > "$TABLE_FILE"
    table_add smtp   host            "$smtp_host"
    table_add smtp   port            "$smtp_port"
    table_add smtp   use_starttls    "$smtp_tls"
    table_add smtp   username        "$smtp_user"
    table_add smtp   from_address    "$from_address"
    patch_config "$candidate" "$TABLE_FILE"
    rm -f "$TABLE_FILE"
    stage_secrets "$password" "$smtp_pass"

    # ---- preview + confirm ----------------------------------------------
    head2 "About to write"
    say ""
    local mask='s/^([+-]?[[:space:]]*(password|token)[[:space:]]*=[[:space:]]*).+/\1<hidden>/'
    if have diff && [ -f "$INSTALL_DIR/config.ini" ]; then
        diff -u "$INSTALL_DIR/config.ini" "$candidate" | sed -E "$mask" | sed -n '1,80p'
    else
        grep -nE '^[[:space:]]*(base_url|domain_id|auth_mode|username|verify_tls|host|port|use_starttls|from_address|template_dir|output_dir|state_dir|log_file)[[:space:]]*=' "$candidate" \
            | sed 's/^/    /'
    fi
    say ""
    info "pairs:"
    pair_summary_lines "$candidate" | while IFS= read -r l; do info "  $l"; done
    say ""
    info "config.ini   (0600) -- no passwords: those go in secrets.env"
    info "secrets.env  (0600) -- sourced by the cron line"
    info "[compare], [normalise] and [property_filters] keep the"
    info "config.example.ini defaults; edit those by hand if you need them."
    say ""
    if ! confirm "Write these files?"; then
        rm -f "$candidate" "$staged_secrets"
        skip "nothing written"
        exit "$EXIT_OK"
    fi

    # ---- prove it, then promote -----------------------------------------
    head2 "Proving the configuration"
    info "running a dry-run comparison against the candidate config..."
    _run_candidate "$candidate" "$staged_secrets" --dry-run --log-level WARNING
    local rc=$?
    case "$rc" in
        0|3) ;;
        *)  rm -f "$candidate" "$staged_secrets"
            say "ERROR:   the report could not run with this configuration"
            say "         (exit $rc). config.ini and secrets.env are unchanged."
            exit "$EXIT_FAIL" ;;
    esac

    if [ -f "$INSTALL_DIR/config.ini" ]; then
        mkdir -p "$INSTALL_DIR/backups"
        cp -p "$INSTALL_DIR/config.ini" \
            "$INSTALL_DIR/backups/config-$(date '+%Y%m%dT%H%M%S').ini.bak"
        info "previous config.ini backed up under backups/"
    fi
    mv "$candidate" "$INSTALL_DIR/config.ini"
    chmod 600 "$INSTALL_DIR/config.ini"
    promote_secrets
    mkdir -p "$INSTALL_DIR/out" "$INSTALL_DIR/state"
    chmod 700 "$INSTALL_DIR/out" "$INSTALL_DIR/state"
    ok "config.ini written and proven against the live server"
    [ "$rc" -eq 3 ] && info "the dry run found drift; the rendered report is in out/"
    return 0
}

# Ask everything about one pair and append its section to $4. Answers come
# from FMDRIFT_SETUP_PAIR<n>_* when set, so an unattended run can add any
# number of pairs.
DEVICES_LISTED=0
# A second file whose pair names a NEW pair may not reuse (add-pair sets it
# to the live config.ini; the wizard, which rebuilds the file, leaves it empty).
EXTRA_NAMES_FILE=""
# Ask everything about one pair. With no 5th argument the answers become a
# new [pair:NAME] section appended to $4. With a section name as the 5th
# argument the pair is EDITED in place in $2: every prompt defaults to the
# current value, so Enter keeps it, and the device and policy listings are
# skipped.
_configure_pair() {
    local i="$1" candidate="$2" secrets="$3" pairs_file="$4" edit_section="${5:-}"
    local P="FMDRIFT_SETUP_PAIR${i}_" v editing=0 name=""
    [ -n "$edit_section" ] && editing=1
    _pair_cur() { [ "$editing" -eq 1 ] && config_value "$candidate" "$edit_section" "$1"; return 0; }
    if [ "$editing" -eq 1 ]; then
        name="${edit_section#*:}"; [ "$edit_section" = "pair" ] && name="default"
        head2 "Pair '$name'"
        info "Enter keeps the current value shown in brackets."
    else
        head2 "Pair $i"
    fi

    local primary secondary filter
    v="${P}PRIMARY"
    if [ "$editing" -eq 0 ] && [ "$DEVICES_LISTED" -eq 0 ] && [ -z "${!v-}" ]; then
        filter="$(ask 'List devices whose name contains (or "all")' 'all' FMDRIFT_SETUP_DEVICE_FILTER)"
        [ "$filter" = "all" ] && filter=""
        info "asking the server for firewall devices..."
        if _run_candidate "$candidate" "$secrets" --list-devices "$filter" --log-level ERROR; then
            DEVICES_LISTED=1
        else
            warn "could not list devices -- the credentials or the URL may be wrong."
            warn "You can still type the names by hand."
        fi
    fi
    primary="$(ask 'Primary firewall (name or id)' "$(_pair_cur primary)" "${P}PRIMARY")"
    secondary="$(ask 'Secondary firewall (name or id)' "$(_pair_cur secondary)" "${P}SECONDARY")"
    reject_unsafe "The primary device" "$primary"
    reject_unsafe "The secondary device" "$secondary"
    [ "$primary" != "$secondary" ] || die "the primary and secondary are the same device."

    if [ "$editing" -eq 0 ]; then
        while true; do
            name="$(ask 'Name for this pair (used in the subject line and --pair)' "pair$i" "${P}NAME")"
            case "$name" in
                *[!A-Za-z0-9._\ -]*|[!A-Za-z0-9]*)
                    die "a pair name is letters, digits, dots, spaces, hyphens or underscores, starting with a letter or digit (got '$name')." ;;
            esac
            if list_pair_names "$pairs_file" | grep -qixF "$name" \
               || { [ -n "$EXTRA_NAMES_FILE" ] && list_all_pair_names "$EXTRA_NAMES_FILE" | grep -qixF "$name"; }; then
                v="${P}NAME"
                [ -z "${!v-}" ] || die "a pair named '$name' already exists."
                printf 'A pair named %s already exists; choose another.\n' "$name" >&2
                continue
            fi
            break
        done
    fi

    # ---- policies --------------------------------------------------------
    local policies_in policies='' pairs_tmp cur_policies
    pairs_tmp="$(mktemp)"
    v="${P}POLICIES"
    if [ "$editing" -eq 0 ] && [ -z "${!v-}" ]; then
        info "asking the server which policies each firewall carries..."
        if ! _run_candidate "$candidate" "$secrets" --primary "$primary" --secondary "$secondary" \
                --list-policies --log-level ERROR; then
            warn "could not list the policies. Check the device names above."
            rm -f "$candidate" "$secrets" "$pairs_tmp"
            die "nothing was written."
        fi
    fi
    cur_policies="$(_pair_cur policies)"
    policies_in="$(ask 'Policy pairs to compare, as "primary policy = secondary policy", comma-separated; or "all" for every rule on each device' "${cur_policies:-all}" "${P}POLICIES")"
    case "$(printf '%s' "$policies_in" | tr '[:upper:]' '[:lower:]')" in
        all|'') info "every policy; rules matched across the device" ;;
        *) _parse_policy_pairs "$policies_in" "policy pair" "$pairs_tmp" >/dev/null
           policies="$(paste -sd ',' "$pairs_tmp" | sed 's/,/, /g')"
           info "comparing: $policies" ;;
    esac
    rm -f "$pairs_tmp"

    # ---- how rules are paired up -----------------------------------------
    local match_by cur_match
    cur_match="$(_pair_cur match_by)"
    if [ "$editing" -eq 0 ]; then
        info "Rules are normally matched by NAME, which suits two policies that mirror"
        info "each other. If these two firewalls carry the SAME policy from the same"
        info "manager (an HA pair, or two devices assigned one FMC access control"
        info "policy), matching by the vendor's rule id reports a renamed rule as a"
        info "rename instead of one missing rule plus one extra."
    fi
    match_by="$(ask 'Match rules by: name, or vendor_id' "${cur_match:-name}" "${P}MATCH_BY")"
    match_by="$(printf '%s' "$match_by" | tr '[:upper:]' '[:lower:]' | tr -d ' ')"
    case "$match_by" in
        name|vendor_id) ;;
        vendor|vendorid|uuid|id) match_by="vendor_id" ;;
        *) die "match rules by 'name' or 'vendor_id' (got '$match_by')." ;;
    esac

    # ---- filters ---------------------------------------------------------
    local survey categories='' change_requests='' applications='' value cur_value
    if [ "$editing" -eq 0 ]; then
        survey="$(ask 'Survey the categories and rule-doc properties in use on this pair? (takes a minute)' 'no' FMDRIFT_SETUP_LIST_PROPERTIES)"
        if [ "$(yesno_to_bool "$survey")" = "true" ]; then
            _run_candidate "$candidate" "$secrets" --primary "$primary" --secondary "$secondary" \
                --list-properties --log-level ERROR || warn "the survey failed; carrying on"
        fi
    fi
    cur_value="$(_pair_cur categories)"
    value="$(ask 'Categories to cover (comma-separated globs), or "all"' "${cur_value:-all}" "${P}CATEGORIES")"
    case "$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')" in
        all|'') ;;
        *) categories="$(_parse_plain_list "$value" "category")" ;;
    esac
    cur_value="$(_pair_cur change_requests)"
    value="$(ask 'Change request numbers (comma-separated), or "none"' "${cur_value:-none}" "${P}CHANGE_REQUESTS")"
    case "$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')" in
        none|'') ;;
        *) change_requests="$(_parse_plain_list "$value" "change request")" ;;
    esac
    cur_value="$(_pair_cur applications)"
    value="$(ask 'Applications (comma-separated globs), or "none"' "${cur_value:-none}" "${P}APPLICATIONS")"
    case "$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')" in
        none|'') ;;
        *) applications="$(_parse_plain_list "$value" "application")" ;;
    esac

    # ---- email -----------------------------------------------------------
    local recipients='' send_when cur_rcpt cur_sw
    cur_rcpt="$(_pair_cur recipients)"
    [ "$editing" -eq 1 ] && cur_rcpt="${cur_rcpt:-none}"
    value="$(ask 'Recipients for this pair (comma-separated), or "none" to only write the report to out/' "$cur_rcpt" "${P}RECIPIENTS")"
    case "$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')" in
        none) ;;
        *) recipients="$(_parse_email_list "$value" "recipient")" ;;
    esac
    cur_sw="$(_pair_cur send_when)"
    [ "$cur_sw" = "never" ] && [ -n "$recipients" ] && cur_sw="drift"
    send_when="$(ask 'Send when? drift = only when differences exist; always = every run; changes = only when something is new or resolved' "${cur_sw:-drift}" "${P}SEND_WHEN")"
    send_when="$(printf '%s' "$send_when" | tr '[:upper:]' '[:lower:]')"
    case "$send_when" in
        drift|always|changes) ;;
        never) [ -z "$recipients" ] || warn "send_when=never: the recipients will not be mailed" ;;
        *) die "send_when must be drift, always or changes (got '$send_when')." ;;
    esac
    [ -n "$recipients" ] || send_when="never"

    if [ "$editing" -eq 1 ]; then
        set_section_key "$candidate" "$edit_section" primary         "$primary"
        set_section_key "$candidate" "$edit_section" secondary       "$secondary"
        set_section_key "$candidate" "$edit_section" policies        "${policies:-all}"
        set_section_key "$candidate" "$edit_section" match_by        "$match_by"
        set_section_key "$candidate" "$edit_section" categories      "${categories:-all}"
        set_section_key "$candidate" "$edit_section" change_requests "${change_requests:-none}"
        set_section_key "$candidate" "$edit_section" applications    "${applications:-none}"
        set_section_key "$candidate" "$edit_section" recipients      "${recipients:-none}"
        set_section_key "$candidate" "$edit_section" send_when       "$send_when"
        ok "pair '$name': $primary -> $secondary, matched by $match_by, ${recipients:-no email}, send_when=$send_when"
    else
        append_pair_section "$pairs_file" "$name" "$primary" "$secondary" "$policies" \
            "$categories" "$change_requests" "$applications" "$recipients" "$send_when" "$match_by"
        ok "pair '$name': $primary -> $secondary, matched by $match_by, ${recipients:-no email}, send_when=$send_when"
    fi
    LAST_PAIR_NAME="$name"
}
LAST_PAIR_NAME=""

stage_secrets() {
    local fm_pass="$1" smtp_pass="$2" tmp="$INSTALL_DIR/secrets.env.new"
    local esc_fm esc_smtp
    esc_fm="${fm_pass//\'/\'\\\'\'}"
    esc_smtp="${smtp_pass//\'/\'\\\'\'}"

    : > "$tmp"
    chmod 600 "$tmp"
    printf '# FireMon drift report secrets. Sourced by the cron line; mode 0600.\n' >> "$tmp"
    printf '# Written by setup.sh -- edit by hand if a password changes.\n' >> "$tmp"
    printf "export FMDRIFT_PASSWORD='%s'\n" "$esc_fm" >> "$tmp"
    if [ -n "$smtp_pass" ]; then
        printf "export FMDRIFT_SMTP_PASSWORD='%s'\n" "$esc_smtp" >> "$tmp"
    fi

    local recovered
    recovered="$( unset FMDRIFT_PASSWORD; . "$tmp" >/dev/null 2>&1; printf '%s' "${FMDRIFT_PASSWORD-}" )"
    if [ "$recovered" != "$fm_pass" ]; then
        rm -f "$tmp"
        die "secrets.env did not read back as written -- the password contains something this script cannot quote. Set FMDRIFT_PASSWORD in the environment instead."
    fi
}

promote_secrets() {
    local tmp="$INSTALL_DIR/secrets.env.new"
    [ -f "$tmp" ] || return 0
    if [ -f "$INSTALL_DIR/secrets.env" ]; then
        mkdir -p "$INSTALL_DIR/backups"
        cp -p "$INSTALL_DIR/secrets.env" \
            "$INSTALL_DIR/backups/secrets-$(date '+%Y%m%dT%H%M%S').env.bak"
        chmod 600 "$INSTALL_DIR/backups"/secrets-*.env.bak 2>/dev/null
    fi
    mv "$tmp" "$INSTALL_DIR/secrets.env"
    chmod 600 "$INSTALL_DIR/secrets.env"
    prune_secret_backups
    ok "secrets.env written (0600); no password is stored in config.ini"
}

write_secrets() {
    stage_secrets "$1" "$2" && promote_secrets
}

need_config() {
    [ -f "$INSTALL_DIR/config.ini" ] \
        || die "no config.ini in $INSTALL_DIR. Run: bash setup.sh configure"
    [ -f "$INSTALL_DIR/secrets.env" ] \
        || die "no secrets.env in $INSTALL_DIR. Run: bash setup.sh configure"
}

run_drift() {
    ( set -a; . "$INSTALL_DIR/secrets.env"; set +a
      python3 "$INSTALL_DIR/run_drift.py" --config "$INSTALL_DIR/config.ini" "$@" )
}

# Turn the report's exit code into a line for the operator; returns non-zero
# only for a genuine failure.
report_outcome() {
    local rc="$1"
    case "$rc" in
        0) ok "no drift between the two firewalls"; return 0 ;;
        3) ok "drift found -- see the report"; return 0 ;;
        2) warn "the comparison ran but the email could not be sent; see the ledger in out/"; return 2 ;;
        *) return "$rc" ;;
    esac
}

do_verify() {
    need_config
    head2 "Self-test"
    if python3 "$INSTALL_DIR/run_tests.py" >/dev/null 2>"$INSTALL_DIR/.tests.err"; then
        ok "the unit tests pass under this interpreter"
    else
        say "ERROR:   the unit tests failed. The install is not healthy:"
        while IFS= read -r l; do say "           $l"; done \
            < <(tail -n 20 "$INSTALL_DIR/.tests.err")
        rm -f "$INSTALL_DIR/.tests.err"
        exit "$EXIT_FAIL"
    fi
    rm -f "$INSTALL_DIR/.tests.err"

    head2 "Devices and policies"
    run_drift --list-policies --log-level WARNING
    local rc=$?
    [ "$rc" -eq 0 ] || die "--list-policies exited $rc." "$rc"

    head2 "Dry-run comparison"
    run_drift --dry-run --log-level WARNING
    rc=$?
    report_outcome "$rc" || die "the dry run failed (exit $rc)." "$rc"
    local newest
    newest="$(ls -1t "$INSTALL_DIR/out"/*.eml 2>/dev/null | head -n 1)"
    if [ -n "$newest" ]; then
        ok "the rendered report is in $INSTALL_DIR/out"
        action "copy $newest off the box and open it in Outlook -- it displays"
        action "exactly as a received message, attachment and all."
    fi

    if [ -n "$OPT_SEND_TEST" ]; then
        head2 "Real send to a test address"
        info "sending the report to $OPT_SEND_TEST (the real recipients are"
        info "stamped into the subject, and are not mailed)"
        run_drift --to-override "$OPT_SEND_TEST" --send-when always --log-level INFO
        rc=$?
        report_outcome "$rc" || warn "the send exited $rc; check the ledger."
    fi

    head2 "Did mail leave the box?"
    if have mailq; then
        local queued
        queued="$(mail_queue_count)"
        info "mail queue holds $queued message(s)"
        [ "$queued" != "0" ] && [ "$queued" != "?" ] \
            && action "anything queued is NOT delivered. Run mailq and read the reason under each entry."
    else
        info "mailq not present -- check delivery from wherever your relay is"
    fi
    if have postconf; then
        info "relayhost:        $(postconf -h relayhost 2>/dev/null)"
        info "myhostname:       $(postconf -h myhostname 2>/dev/null)"
        info "sender_canonical: $(postconf -h sender_canonical_maps 2>/dev/null)"
    fi
    action "nothing above proves delivery. 'accepted by the relay' is the last"
    action "thing any SMTP client can observe. See DEPLOYMENT.md section 5."
}

do_run() {
    need_config
    head2 "Run now"
    local redirect="$OPT_SEND_TEST"
    if [ -n "$redirect" ]; then
        info "the report will be sent to $redirect (a test send), whatever"
        info "send_when says; the real recipients are named in the subject."
    else
        warn "this compares every pair NOW and, where its send_when allows, mails"
        warn "the REAL recipients:"
        pair_summary_lines "$INSTALL_DIR/config.ini" | while IFS= read -r l; do warn "  $l"; done
        warn "use --send-test ADDR to send everything to yourself instead."
    fi
    confirm "Run now?" || { skip "nothing run"; exit "$EXIT_OK"; }

    head2 "Running"
    if [ -n "$redirect" ]; then
        run_drift --to-override "$redirect" --send-when always --log-level INFO
    else
        run_drift --log-level INFO
    fi
    local rc=$?
    report_outcome "$rc" || {
        [ "$rc" -eq 2 ] && return 2
        die "the run failed (exit $rc)." "$rc"
    }
    if have mailq; then
        local queued; queued="$(mail_queue_count)"
        info "mail queue holds $queued message(s)"
        [ "$queued" != "0" ] && [ "$queued" != "?" ] \
            && action "anything queued is NOT delivered. Run mailq and read the reason under each entry."
    fi
    return 0
}

do_schedule() {
    need_config
    have crontab || die "no crontab command on this host. Scheduling needs one; configuration does not."

    head2 "Re-checking the configuration"
    run_drift --list-policies --log-level ERROR >/dev/null
    local rc=$?
    [ "$rc" -eq 0 ] || die "--list-policies exited $rc -- fix that before scheduling." "$rc"
    ok "the report runs and authenticates"

    local flags=' --dry-run'
    if [ "$OPT_LIVE" -eq 1 ]; then
        if [ "$OPT_MAIL_PROVEN" -ne 1 ]; then
            say "ERROR:   --live schedules real mail, so it needs --mail-proven as"
            say "         well: confirmation that you have run a live send and"
            say "         checked that mailq was empty afterwards. DEPLOYMENT.md"
            say "         section 5 covers it."
            exit "$EXIT_FAIL"
        fi
        flags=''
    else
        info "scheduling with --dry-run. It will render to out/ and send nothing."
        info "Promote it with: bash setup.sh schedule --live --mail-proven"
    fi

    rehearse_cron

    head2 "Crontab"
    local existing stripped unmanaged
    existing="$(crontab_read)"
    crontab_backup "$existing"

    stripped="$(strip_block "$existing" "$MARK_OPEN" "$MARK_CLOSE")"
    stripped="$(strip_block "$stripped" "$TRIM_OPEN" "$TRIM_CLOSE")"

    unmanaged="$(printf '%s\n' "$stripped" | grep 'run_drift\.py' || true)"
    if [ -n "$unmanaged" ]; then
        warn "the crontab runs the report from outside the managed block:"
        while IFS= read -r l; do say "           $l"; done <<< "$unmanaged"
        if [ "$OPT_ADOPT" -eq 1 ]; then
            warn "--adopt given: that line will be replaced by the managed block."
        elif confirm "Replace it with a managed block?"; then
            :
        else
            die "stopping. Two jobs would mail the report twice."
        fi
        stripped="$(printf '%s\n' "$stripped" | grep -v 'run_drift\.py')"
    fi

    local block
    block="$(build_managed_block "$flags" "$(trailing_mailto "$stripped")")"

    local updated
    if [ -z "$(printf '%s' "$stripped" | tr -d '[:space:]')" ]; then
        updated="$block"
    else
        updated="$stripped
$block"
    fi

    crontab_write "$updated" "$MARK_OPEN"
    ok "cron entry installed: $CRON_SPEC"
    info "$(drift_cron_line "$flags")"
    info "previous crontab: $LAST_BACKUP"
    if [ "$OPT_LOGROTATE" -eq 1 ]; then
        info "log rotation on (monthly): cron.log is trimmed and out/ files"
        action "older than 90 days are deleted -- including run ledgers and"
        action "rendered reports. Use --no-logrotate for a longer record."
    else
        info "log rotation OFF (--no-logrotate). out/ and cron.log grow unbounded."
    fi
    if [ "$OPT_LIVE" -eq 1 ]; then
        action "it will send real mail. Run mailq after the first run."
    else
        action "it is scheduled with --dry-run. Read out/ after the first run,"
        action "then: bash setup.sh schedule --live --mail-proven"
    fi
}

do_unschedule() {
    have crontab || die "no crontab command on this host."
    local existing stripped
    existing="$(crontab_read)"
    if ! printf '%s\n' "$existing" | grep -qxF "$MARK_OPEN"; then
        skip "no managed drift block in the crontab"
        return 0
    fi
    crontab_backup "$existing"
    stripped="$(strip_block "$existing" "$MARK_OPEN" "$MARK_CLOSE")"
    stripped="$(strip_block "$stripped" "$TRIM_OPEN" "$TRIM_CLOSE")"
    crontab_write "$stripped" ""
    ok "cron entry removed. Files and logs are untouched."
}

do_restore_crontab() {
    have crontab || die "no crontab command on this host."
    local file="$POSITIONAL_ARG"
    if [ -z "$file" ]; then
        file="$(ls -1t "$INSTALL_DIR/backups"/crontab-*.bak 2>/dev/null | head -n 1)"
        [ -n "$file" ] || die "no crontab backups in $INSTALL_DIR/backups"
    fi
    [ -f "$file" ] || die "no such backup: $file"
    head2 "Restoring $file"
    say ""
    sed 's/^/    /' "$file"
    say ""
    confirm "Install this as the crontab?" || { skip "left alone"; exit "$EXIT_OK"; }
    crontab_backup "$(crontab_read)"
    crontab_write "$(cat "$file")" ""
    ok "crontab restored from $file"
}

do_status() {
    head2 "Install"
    say "  directory:     $INSTALL_DIR"
    say "  version:       $(installed_version "$INSTALL_DIR" | sed 's/^$/unknown/')$([ -d "$INSTALL_DIR/.git" ] && printf ' (git clone)')"
    say "  runs as:       $(id -un)"
    say "  python3:       $(python3 -V 2>&1) at $(command -v python3 || echo 'not found')"
    local f
    for f in config.ini secrets.env; do
        if [ -f "$INSTALL_DIR/$f" ]; then
            say "  $f:$(printf '%*s' $((14 - ${#f})) '')mode $(stat -c '%a' "$INSTALL_DIR/$f" 2>/dev/null || echo '?')"
        else
            say "  $f:$(printf '%*s' $((14 - ${#f})) '')not present"
        fi
    done

    if [ -f "$INSTALL_DIR/config.ini" ]; then
        head2 "Configuration"
        local c="$INSTALL_DIR/config.ini"
        say "  base_url:      $(config_value "$c" firemon base_url)"
        say "  domain_id:     $(config_value "$c" firemon domain_id)"
        say "  username:      $(config_value "$c" firemon username)"
        say "  verify_tls:    $(config_value "$c" firemon verify_tls)"
        say "  global recip.: $(config_value "$c" email recipients | sed 's/^$/(none)/')   send_when $(config_value "$c" email send_when)"
        local pairs
        pairs="$(pair_summary_lines "$c")"
        if [ -n "$pairs" ]; then
            say "  pairs:"
            printf '%s\n' "$pairs" | while IFS= read -r l; do say "    $l"; done
        else
            say "  pairs:         NONE -- run: bash setup.sh configure"
        fi
        say "  smtp host:     $(config_value "$c" smtp host):$(config_value "$c" smtp port)"
        say "  from_address:  $(config_value "$c" smtp from_address)"
    fi

    if [ -f "$INSTALL_DIR/secrets.env" ]; then
        head2 "Secrets"
        grep -o '^export [A-Z_]*' "$INSTALL_DIR/secrets.env" 2>/dev/null \
            | sed 's/^export /  defined: /' || say "  (none)"
    fi

    head2 "Schedule"
    if ! have crontab; then
        say "  crontab:       not present on this host"
    else
        local existing
        existing="$(crontab -l 2>/dev/null || true)"
        if printf '%s\n' "$existing" | grep -qxF "$MARK_OPEN"; then
            local line
            line="$(printf '%s\n' "$existing" | grep 'run_drift\.py' | head -n 1)"
            say "  managed block: present"
            say "  line:          $line"
            case "$line" in
                "$CRON_SPEC"*) ;;
                *) say "  note:          the schedule differs from the default $CRON_SPEC" ;;
            esac
            case "$line" in
                *--dry-run*) say "  mode:          DRY RUN -- renders to out/, sends nothing" ;;
                *)           say "  mode:          LIVE -- sends real mail" ;;
            esac
        elif printf '%s\n' "$existing" | grep -q 'run_drift\.py'; then
            say "  managed block: absent, but an unmanaged drift line exists:"
            printf '%s\n' "$existing" | grep 'run_drift\.py' | sed 's/^/      /'
        else
            say "  managed block: not installed"
        fi
    fi

    head2 "Last run"
    if [ -s "$INSTALL_DIR/cron.log" ]; then
        say "  cron.log:      $(wc -c < "$INSTALL_DIR/cron.log") bytes"
        say "  last line:     $(grep -v '^[[:space:]]*$' "$INSTALL_DIR/cron.log" | tail -n 1)"
    else
        say "  cron.log:      never written"
    fi
    local statefile found_state=0
    for statefile in "$INSTALL_DIR/state"/last-*.json; do
        [ -f "$statefile" ] || continue
        found_state=1
        say "  last findings: $(python3 -c 'import json,os,sys; d=json.load(open(sys.argv[1])); c=d.get("counts",{}); n=os.path.basename(sys.argv[1])[5:-5]; print("%s -- %s: differ %s, only primary %s, only secondary %s" % (d.get("run_time","?")[:16], n, c.get("changed","?"), c.get("only_primary","?"), c.get("only_secondary","?")))' "$statefile" 2>/dev/null || basename "$statefile")"
    done
    [ "$found_state" -eq 1 ] || say "  last findings: no live run recorded yet"
    local ledger
    ledger="$(ls -1t "$INSTALL_DIR/out"/ledger-*.jsonl 2>/dev/null | head -n 1)"
    if [ -n "$ledger" ]; then
        say "  last ledger:   $(basename "$ledger") ($(wc -l < "$ledger") entries)"
    else
        say "  last ledger:   none"
    fi

    head2 "Mail"
    if have mailq; then
        say "  queued:        $(mail_queue_count) message(s) -- anything queued is NOT delivered"
    else
        say "  mailq:         not present"
    fi

    local backups
    backups="$(ls -1 "$INSTALL_DIR/backups" 2>/dev/null | wc -l)"
    head2 "Backups"
    say "  $INSTALL_DIR/backups: ${backups:-0} file(s)"
}

# Add one or more email addresses to one, several, or every pair's
# recipients -- the common "a manager wants in" request -- without touching
# anything else in config.ini and without re-running the wizard.
do_add_recipient() {
    need_config
    head2 "Add a recipient"

    local email="$POSITIONAL_ARG"
    if [ -z "$email" ]; then
        email="$(ask 'Email address(es) to add (comma-separated)' '' FMDRIFT_SETUP_NEW_RECIPIENT)"
    fi
    email="$(_parse_email_list "$email" recipient)"

    local pair_list=()
    if [ "${#PAIRS[@]}" -gt 0 ]; then
        pair_list=("${PAIRS[@]}")
    else
        local all_names
        all_names="$(list_all_pair_names "$INSTALL_DIR/config.ini" | tr '\n' ' ')"
        [ -n "$all_names" ] || die "no pairs are configured yet. Run: bash setup.sh configure"
        local choice
        choice="$(ask "Add to which pair(s)? Comma-separated names, or \"all\" (configured: $all_names)" 'all' FMDRIFT_SETUP_RECIPIENT_PAIRS)"
        if [ "$(printf '%s' "$choice" | tr '[:upper:]' '[:lower:]')" = "all" ]; then
            while IFS= read -r n; do [ -n "$n" ] && pair_list+=("$n"); done \
                < <(list_all_pair_names "$INSTALL_DIR/config.ini")
        else
            local IFS=',' item
            for item in $choice; do
                item="$(printf '%s' "$item" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
                [ -n "$item" ] && pair_list+=("$item")
            done
        fi
    fi
    [ "${#pair_list[@]}" -gt 0 ] || die "no pairs to add the recipient to."

    # De-dupe case-insensitively (a repeated --pair, or a name typed twice)
    # so a pair is never processed -- and previewed -- more than once.
    local deduped=() seen_pairs="" name_lower name
    for name in "${pair_list[@]}"; do
        name_lower="$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')"
        case " ${seen_pairs:-} " in
            *" $name_lower "*) continue ;;
        esac
        seen_pairs="${seen_pairs:-} $name_lower"
        deduped+=("$name")
    done
    pair_list=("${deduped[@]}")

    head2 "Checking"
    TABLE_FILE="$(mktemp)"; : > "$TABLE_FILE"
    local changed=0 name section current merged sw reply
    local preview=() bad=() already=() added_pairs=()
    for name in "${pair_list[@]}"; do
        section="$(find_pair_section "$INSTALL_DIR/config.ini" "$name")"
        if [ -z "$section" ]; then
            bad+=("$name")
            continue
        fi
        current="$(config_value "$INSTALL_DIR/config.ini" "$section" recipients)"
        merge_recipients "$current" "$email"   # sets MERGE_RESULT / MERGE_ADDED_COUNT
        if [ "$MERGE_ADDED_COUNT" -eq 0 ]; then
            already+=("$name")
            continue
        fi
        merged="$MERGE_RESULT"
        table_add "$section" recipients "$merged"
        preview+=("[$section] recipients -> $merged")
        added_pairs+=("$name")
        changed=1

        # A pair that started with no recipients has send_when=never (the
        # wizard sets it automatically): a recipient added now would
        # otherwise be mailed nothing until someone notices. Offer to fix it
        # on the spot; --yes or no tty just flags it instead of asking.
        sw="$(config_value "$INSTALL_DIR/config.ini" "$section" send_when)"
        if [ "$sw" = "never" ]; then
            if [ "$OPT_YES" -eq 1 ] || ! { true < /dev/tty; } 2>/dev/null; then
                warn "pair '$name' has send_when=never -- $email will not be mailed there until you change it."
            else
                reply="$(ask "Pair '$name' has send_when=never, so it still won't send anything. Change it now? (drift/always/changes/never)" 'drift' '')"
                case "$(printf '%s' "$reply" | tr '[:upper:]' '[:lower:]')" in
                    drift|always|changes)
                        table_add "$section" send_when "$reply"
                        preview+=("[$section] send_when never -> $reply") ;;
                    never|'') : ;;
                    *) warn "unrecognised value '$reply' -- leaving send_when as never for '$name'" ;;
                esac
            fi
        fi
    done

    if [ "${#bad[@]}" -gt 0 ]; then
        local known; known="$(list_all_pair_names "$INSTALL_DIR/config.ini" | tr '\n' ' ')"
        warn "no such pair: ${bad[*]}. Configured: ${known:-(none)}"
    fi
    if [ "${#already[@]}" -gt 0 ]; then
        info "already has $email: ${already[*]}"
    fi
    if [ "$changed" -eq 0 ]; then
        rm -f "$TABLE_FILE"
        skip "nothing to change"
        [ "${#bad[@]}" -eq 0 ] || exit "$EXIT_FAIL"
        exit "$EXIT_OK"
    fi

    head2 "About to write"
    say ""
    local line
    for line in "${preview[@]}"; do say "    $line"; done
    say ""
    if ! confirm "Write these changes?"; then
        rm -f "$TABLE_FILE"
        skip "nothing written"
        exit "$EXIT_OK"
    fi

    mkdir -p "$INSTALL_DIR/backups" || die "could not create $INSTALL_DIR/backups"
    local backup_path="$INSTALL_DIR/backups/config-$(date '+%Y%m%dT%H%M%S').ini.bak"
    cp -p "$INSTALL_DIR/config.ini" "$backup_path" || die "could not write $backup_path"
    patch_config "$INSTALL_DIR/config.ini" "$TABLE_FILE"
    rm -f "$TABLE_FILE"

    head2 "Confirming the config still loads"
    if run_drift --list-pairs --log-level ERROR >/dev/null 2>"$INSTALL_DIR/.addrecip.err"; then
        ok "config.ini is valid; added $email to: ${added_pairs[*]}"
        info "previous config.ini backed up under $backup_path"
        rm -f "$INSTALL_DIR/.addrecip.err"
    else
        say "ERROR:   the edited config.ini failed to load -- restoring the previous version."
        cp -p "$backup_path" "$INSTALL_DIR/config.ini"
        say "         Restored from $backup_path. It said:"
        if [ -s "$INSTALL_DIR/.addrecip.err" ]; then
            while IFS= read -r l; do say "           $l"; done < "$INSTALL_DIR/.addrecip.err"
        fi
        rm -f "$INSTALL_DIR/.addrecip.err"
        exit "$EXIT_FAIL"
    fi
    action "this applies on the NEXT run. Prove it now with:"
    action "  bash setup.sh run --send-test ${email%%,*}"
}


# ============================================================ pairs =========
#
# add-pair, edit-pair and remove-pair change ONE pair in config.ini without
# redoing the wizard: a candidate copy is edited, previewed, confirmed,
# backed up over, then proven by loading it; a copy that fails to load is
# rolled back. Each pair has its own recipients and send rule, so this is
# also how "send this pair's report to these people" is set.

# Which pair a verb acts on: the argument, --pair, or a prompt.
_pick_pair() {
    local name="$POSITIONAL_ARG" names
    [ -n "$name" ] || [ "${#PAIRS[@]}" -eq 0 ] || name="${PAIRS[0]}"
    names="$(list_all_pair_names "$INSTALL_DIR/config.ini" | tr '\n' ' ')"
    [ -n "$names" ] || die "no pairs are configured yet. Run: bash setup.sh add-pair"
    if [ -z "$name" ]; then
        info "configured pairs:"
        pair_summary_lines "$INSTALL_DIR/config.ini" | while IFS= read -r l; do info "  $l"; done
        name="$(ask "Which pair? ($names)" '' FMDRIFT_SETUP_TARGET_PAIR)"
    fi
    PICKED_SECTION="$(find_pair_section "$INSTALL_DIR/config.ini" "$name")"
    [ -n "$PICKED_SECTION" ] || die "no pair named '$name'. Configured: $names"
    PICKED_NAME="$name"
    [ "$PICKED_SECTION" = "pair" ] && PICKED_NAME="default"
}
PICKED_SECTION=""
PICKED_NAME=""

# Preview a candidate config against the live one, confirm, back up, write,
# prove it loads (roll back if not), then offer a dry run of the pair.
_commit_pair_change() {
    local candidate="$1" what="$2" pair="${3:-}"
    head2 "About to write"
    say ""
    if have diff; then
        diff -u "$INSTALL_DIR/config.ini" "$candidate" | sed -n '3,120p' | sed 's/^/    /'
    else
        info "pairs after the change:"
        pair_summary_lines "$candidate" | while IFS= read -r l; do info "  $l"; done
    fi
    say ""
    if ! confirm "Write this change to config.ini?"; then
        rm -f "$candidate"
        skip "nothing written"
        exit "$EXIT_OK"
    fi
    mkdir -p "$INSTALL_DIR/backups" || die "could not create $INSTALL_DIR/backups"
    local backup_path="$INSTALL_DIR/backups/config-$(date '+%Y%m%dT%H%M%S').ini.bak"
    cp -p "$INSTALL_DIR/config.ini" "$backup_path" || die "could not write $backup_path"
    mv "$candidate" "$INSTALL_DIR/config.ini"
    chmod 600 "$INSTALL_DIR/config.ini"

    head2 "Confirming the config still loads"
    if run_drift --list-pairs --log-level ERROR >/dev/null 2>"$INSTALL_DIR/.pair.err"; then
        ok "config.ini is valid: $what"
        info "previous config.ini backed up under $backup_path"
        rm -f "$INSTALL_DIR/.pair.err"
    else
        say "ERROR:   the edited config.ini failed to load -- restoring the previous version."
        cp -p "$backup_path" "$INSTALL_DIR/config.ini"
        say "         Restored from $backup_path. It said:"
        if [ -s "$INSTALL_DIR/.pair.err" ]; then
            while IFS= read -r l; do say "           $l"; done < "$INSTALL_DIR/.pair.err"
        fi
        rm -f "$INSTALL_DIR/.pair.err"
        exit "$EXIT_FAIL"
    fi
    if [ -n "$pair" ]; then
        if { true < /dev/tty; } 2>/dev/null && [ "$OPT_YES" -eq 0 ] \
           && confirm "Prove pair '$pair' against the live server with a dry-run comparison now? (sends nothing)"; then
            run_drift --pair "$pair" --dry-run --log-level WARNING
            report_outcome $? || warn "the dry run exited $?; check the pair's devices and policies."
        else
            action "prove it when convenient:  bash setup.sh verify"
        fi
        if [ "$(config_value "$INSTALL_DIR/config.ini" "$(find_pair_section "$INSTALL_DIR/config.ini" "$pair")" send_when)" != "never" ]; then
            action "this pair is mailed on the schedule's next run; to send it now:"
            action "  bash setup.sh run"
        fi
    fi
}

do_add_pair() {
    need_config
    head2 "Add a pair"
    info "a pair is two firewalls whose policies should match: the primary is"
    info "the reference, the secondary is expected to mirror it. The pair gets"
    info "its own recipients, send rule, filters and last-run state."
    local candidate="$INSTALL_DIR/config.ini.new" pairs_file
    cp -p "$INSTALL_DIR/config.ini" "$candidate" || die "could not copy config.ini"
    pairs_file="$(mktemp)"; : > "$pairs_file"
    DEVICES_LISTED=0
    EXTRA_NAMES_FILE="$INSTALL_DIR/config.ini"
    _configure_pair 1 "$candidate" "$INSTALL_DIR/secrets.env" "$pairs_file"
    insert_before_section "$candidate" compare "$pairs_file"
    rm -f "$pairs_file"
    _commit_pair_change "$candidate" "pair '$LAST_PAIR_NAME' added" "$LAST_PAIR_NAME"
}

do_edit_pair() {
    need_config
    head2 "Modify a pair"
    _pick_pair
    info "current: $(pair_summary_lines "$INSTALL_DIR/config.ini" | grep -i "^$PICKED_NAME:" | head -n 1)"
    local candidate="$INSTALL_DIR/config.ini.new"
    cp -p "$INSTALL_DIR/config.ini" "$candidate" || die "could not copy config.ini"
    _configure_pair 1 "$candidate" "$INSTALL_DIR/secrets.env" "" "$PICKED_SECTION"
    if cmp -s "$candidate" "$INSTALL_DIR/config.ini"; then
        rm -f "$candidate"
        skip "nothing changed"
        return 0
    fi
    _commit_pair_change "$candidate" "pair '$PICKED_NAME' updated" "$PICKED_NAME"
}

do_remove_pair() {
    need_config
    head2 "Remove a pair"
    _pick_pair
    info "removing: $(pair_summary_lines "$INSTALL_DIR/config.ini" | grep -i "^$PICKED_NAME:" | head -n 1)"
    local remaining
    remaining="$(list_all_pair_names "$INSTALL_DIR/config.ini" | grep -vixF "$PICKED_NAME" | wc -l)"
    [ "$remaining" -gt 0 ] || warn "this is the only pair; the scheduled run will have nothing to compare until one is added."
    confirm "Remove pair '$PICKED_NAME' from config.ini?" || { skip "nothing removed"; exit "$EXIT_OK"; }
    local candidate="$INSTALL_DIR/config.ini.new"
    cp -p "$INSTALL_DIR/config.ini" "$candidate" || die "could not copy config.ini"
    if [ "$PICKED_SECTION" = "pair" ]; then
        # The single-pair shorthand has no section to drop: blank its devices.
        TABLE_FILE="$(mktemp)"; : > "$TABLE_FILE"
        table_add pair primary ""
        table_add pair secondary ""
        patch_config "$candidate" "$TABLE_FILE"
        rm -f "$TABLE_FILE"
    else
        remove_pair_sections "$candidate" "$PICKED_NAME"
    fi
    _commit_pair_change "$candidate" "pair '$PICKED_NAME' removed"
    local statefile
    statefile="$(pair_state_file "$PICKED_NAME")"
    if [ -f "$statefile" ]; then
        rm -f "$statefile"
        info "its last-run state ($(basename "$statefile")) was removed; out/ keeps its past reports"
    fi
}

do_list_pairs() {
    need_config
    head2 "Pairs"
    local lines
    lines="$(pair_summary_lines "$INSTALL_DIR/config.ini")"
    if [ -z "$lines" ]; then
        info "none configured. Add one with: bash setup.sh add-pair"
        return 0
    fi
    printf '%s\n' "$lines" | while IFS= read -r l; do say "  $l"; done
    say ""
    info "as the report resolves them (with inherited defaults):"
    run_drift --list-pairs --log-level ERROR 2>/dev/null | sed 's/^/  /' || warn "config.ini does not load; run: bash setup.sh status"
}

do_pairs_menu() {
    MENU_BUILDER="_menu_build_pairs"
    MENU_TITLE="Firewall pairs"
    do_menu
}

do_uninstall() {
    head2 "Uninstall"
    if have crontab; then
        do_unschedule
    fi
    if [ -f "$INSTALL_DIR/secrets.env" ] && confirm "Delete secrets.env (it holds the password)?"; then
        rm -f "$INSTALL_DIR/secrets.env"
        ok "secrets.env deleted"
    fi
    if [ -f "$INSTALL_DIR/config.ini" ] && confirm "Archive config.ini to backups/?"; then
        mkdir -p "$INSTALL_DIR/backups"
        mv "$INSTALL_DIR/config.ini" \
            "$INSTALL_DIR/backups/config-removed-$(date '+%Y%m%dT%H%M%S').ini.bak"
        ok "config.ini moved to backups/"
    fi
    prune_secret_backups
    info "out/, state/, cron.log and drift.log were left alone -- they are the"
    info "only record of what was found and sent."
}

prune_secret_backups() {
    ls -1t "$INSTALL_DIR/backups"/secrets-*.env.bak 2>/dev/null | tail -n +4 \
        | while IFS= read -r old; do rm -f "$old"; done
}


# ================================================================ update ====
#
# Replace the program files with a newer release, keeping everything the
# operator made: config.ini, secrets.env, state/, out/, backups/, the logs and
# the crontab. The files being replaced are archived to backups/ first, the
# unit tests are run on the result, and a failure rolls the files back.
#
# Where the new files come from, in order:
#   --source PATH   a directory, or a .tar.gz / .zip, already on the box --
#                   for an appliance with no route to the internet.
#   --source URL    any URL curl can fetch a tarball or zip from.
#   a git clone     if the install directory is one and git is present,
#                   `git pull --ff-only` does the work.
#   GitHub          the tarball of $UPDATE_REF from github.com/$UPDATE_REPO.
#
# Every file is swapped in with mv (a rename), never written in place: this
# script is itself one of the files, and bash reads a script as it runs, so
# overwriting setup.sh under a running copy would execute garbage. A rename
# leaves the running copy its old inode.

UPDATE_REPO="${FMDRIFT_UPDATE_REPO:-adamgunderson/FireMon-Policy-Drift}"
UPDATE_REF="${FMDRIFT_UPDATE_REF:-main}"
# The program files -- what an update replaces. Nothing else is touched.
UPDATE_FILES=(firemon_drift templates tests run_drift.py run_tests.py setup.sh
              config.example.ini README.md DEPLOYMENT.md)

installed_version() {
    sed -n 's/^__version__ *= *"\([^"]*\)".*/\1/p' "$1/firemon_drift/__init__.py" 2>/dev/null \
        | head -n 1
}

# 0 when $1 is a newer dotted version than $2.
version_newer() {
    [ -n "$1" ] && [ -n "$2" ] && [ "$1" != "$2" ] \
        && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n 1)" = "$1" ]
}

update_source_label() {
    if [ -n "$OPT_SOURCE" ]; then printf '%s' "$OPT_SOURCE"
    else printf 'github.com/%s (%s)' "$UPDATE_REPO" "$UPDATE_REF"; fi
}

# Fetch and unpack the new release under $1 (a scratch directory). Prints the
# directory that holds run_drift.py. Non-zero when nothing usable arrived.
update_fetch() {
    local scratch="$1" src="$OPT_SOURCE" archive url root
    if [ -n "$src" ] && [ -d "$src" ]; then
        [ -f "$src/run_drift.py" ] || { say_err "ERROR:   $src does not hold run_drift.py"; return 1; }
        printf '%s' "$src"
        return 0
    fi
    if [ -n "$src" ] && [ -f "$src" ]; then
        archive="$src"
    else
        url="${src:-https://github.com/$UPDATE_REPO/archive/refs/heads/$UPDATE_REF.tar.gz}"
        have curl || { say_err "ERROR:   curl is needed to download $url"; return 1; }
        case "$url" in *.zip) archive="$scratch/release.zip" ;; *) archive="$scratch/release.tar.gz" ;; esac
        say_err "         downloading $url"
        curl -fsSL --retry 2 --connect-timeout 20 -o "$archive" "$url" \
            || { say_err "ERROR:   download failed: $url"; return 1; }
    fi
    mkdir -p "$scratch/tree"
    case "$archive" in
        *.zip)
            have unzip || { say_err "ERROR:   unzip is needed for $archive"; return 1; }
            unzip -q "$archive" -d "$scratch/tree" || { say_err "ERROR:   could not unzip $archive"; return 1; } ;;
        *)
            tar -xzf "$archive" -C "$scratch/tree" || { say_err "ERROR:   could not unpack $archive"; return 1; } ;;
    esac
    # A GitHub tarball wraps everything in <repo>-<ref>/; a hand-made one may not.
    root="$(find "$scratch/tree" -maxdepth 3 -name run_drift.py 2>/dev/null | head -n 1)"
    [ -n "$root" ] || { say_err "ERROR:   the archive does not hold run_drift.py"; return 1; }
    printf '%s' "$(dirname "$root")"
}

# Archive the program files about to be replaced. Prints the archive path.
update_backup() {
    local stamp present=() f archive
    stamp="$(date '+%Y%m%dT%H%M%S')"
    mkdir -p "$INSTALL_DIR/backups"
    archive="$INSTALL_DIR/backups/code-$stamp.tar.gz"
    for f in "${UPDATE_FILES[@]}"; do [ -e "$INSTALL_DIR/$f" ] && present+=("$f"); done
    if [ "${#present[@]}" -eq 0 ]; then
        printf ''
        return 0
    fi
    ( cd "$INSTALL_DIR" && tar -czf "$archive" "${present[@]}" ) || return 1
    printf '%s' "$archive"
}

# Swap the program files in from $1. Each file lands via rename.
update_apply() {
    local src="$1" f
    for f in "${UPDATE_FILES[@]}"; do
        [ -e "$src/$f" ] || continue
        rm -rf "$INSTALL_DIR/$f.new" "$INSTALL_DIR/$f.old"
        if [ -d "$src/$f" ]; then
            cp -R "$src/$f" "$INSTALL_DIR/$f.new" || return 1
            find "$INSTALL_DIR/$f.new" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null
            if [ -e "$INSTALL_DIR/$f" ]; then
                mv "$INSTALL_DIR/$f" "$INSTALL_DIR/$f.old" || return 1
            fi
            mv "$INSTALL_DIR/$f.new" "$INSTALL_DIR/$f" || return 1
            rm -rf "$INSTALL_DIR/$f.old"
        else
            cp "$src/$f" "$INSTALL_DIR/$f.new" || return 1
            mv -f "$INSTALL_DIR/$f.new" "$INSTALL_DIR/$f" || return 1
        fi
    done
    chmod 755 "$INSTALL_DIR/setup.sh" "$INSTALL_DIR/run_drift.py" "$INSTALL_DIR/run_tests.py" 2>/dev/null
    return 0
}

# Put the archived program files back after a failed update.
update_rollback() {
    local archive="$1" f
    [ -n "$archive" ] && [ -f "$archive" ] || return 1
    for f in "${UPDATE_FILES[@]}"; do rm -rf "$INSTALL_DIR/$f"; done
    ( cd "$INSTALL_DIR" && tar -xzf "$archive" )
}

# The unit tests on the installed files. Overridable by the tests of this
# script, which have no interpreter to spare.
update_selftest() {
    python3 "$INSTALL_DIR/run_tests.py" >/dev/null 2>"$INSTALL_DIR/.tests.err"
}

do_update() {
    head2 "Update"
    local current new scratch root backup rc
    current="$(installed_version "$INSTALL_DIR")"
    info "installed: ${current:-unknown}   ($INSTALL_DIR)"

    # ---- a git clone: git knows how ----------------------------------------
    if [ -z "$OPT_SOURCE" ] && [ -d "$INSTALL_DIR/.git" ] && have git; then
        local origin behind
        origin="$(git -C "$INSTALL_DIR" remote get-url origin 2>/dev/null || echo 'origin')"
        info "this install is a git clone of $origin"
        git -C "$INSTALL_DIR" fetch -q origin || die "git fetch failed; check the network and the remote."
        behind="$(git -C "$INSTALL_DIR" rev-list --count 'HEAD..@{u}' 2>/dev/null || echo '?')"
        if [ "$behind" = "0" ]; then
            ok "up to date with $origin"
            return 0
        fi
        info "$behind commit(s) available"
        if [ "$OPT_CHECK" -eq 1 ]; then
            action "update with: bash setup.sh update"
            return 0
        fi
        if [ -n "$(git -C "$INSTALL_DIR" status --porcelain -- "${UPDATE_FILES[@]}" 2>/dev/null)" ]; then
            warn "program files have local changes; git will refuse to overwrite them."
        fi
        confirm "Pull the latest from $origin?" || { skip "not updated"; return 0; }
        git -C "$INSTALL_DIR" pull --ff-only origin || die "git pull failed. Resolve it by hand, or clone afresh."
        backup=""
    else
    # ---- a tarball, a zip or a directory -----------------------------------
        scratch="$(mktemp -d)"
        root="$(update_fetch "$scratch")"
        if [ -z "$root" ]; then
            rm -rf "$scratch"
            die "could not get the update from $(update_source_label).
         On a box with no internet access, download the release elsewhere and run:
           bash setup.sh update --source /path/to/FireMon-Policy-Drift.tar.gz"
        fi
        new="$(installed_version "$root")"
        info "available: ${new:-unknown}   ($(update_source_label))"
        if [ "$OPT_CHECK" -eq 1 ]; then
            if [ -n "$new" ] && [ -n "$current" ] && ! version_newer "$new" "$current"; then
                ok "up to date ($current)"
            else
                action "update available: bash setup.sh update"
            fi
            rm -rf "$scratch"
            return 0
        fi
        if [ -n "$new" ] && [ -n "$current" ] && [ "$new" = "$current" ]; then
            info "the same version is installed; the files will still be refreshed."
        elif [ -n "$new" ] && [ -n "$current" ] && version_newer "$current" "$new"; then
            warn "the installed version ($current) is NEWER than the one on offer ($new)."
        fi
        info "kept as they are: config.ini, secrets.env, state/, out/, backups/, logs, crontab"
        if ! confirm "Replace the program files in $INSTALL_DIR with version ${new:-unknown}?"; then
            rm -rf "$scratch"
            skip "not updated"
            return 0
        fi
        backup="$(update_backup)" || { rm -rf "$scratch"; die "could not archive the current files to backups/; nothing was changed."; }
        [ -n "$backup" ] && info "previous files archived to $backup"
        if ! update_apply "$root"; then
            rm -rf "$scratch"
            if [ -n "$backup" ] && update_rollback "$backup"; then
                die "the update failed part way; the previous files were put back."
            fi
            die "the update failed part way. Restore by hand from $backup"
        fi
        rm -rf "$scratch"
        ok "program files replaced"
    fi

    # ---- prove the result ---------------------------------------------------
    head2 "Self-test"
    if update_selftest; then
        rm -f "$INSTALL_DIR/.tests.err"
        ok "the unit tests pass under $(python3 -V 2>&1)"
    else
        say "ERROR:   the unit tests failed on the new files:"
        while IFS= read -r l; do say "           $l"; done \
            < <(tail -n 20 "$INSTALL_DIR/.tests.err" 2>/dev/null)
        rm -f "$INSTALL_DIR/.tests.err"
        if [ -n "$backup" ] && update_rollback "$backup"; then
            warn "rolled back to the previous files ($(installed_version "$INSTALL_DIR"))."
        elif [ -d "$INSTALL_DIR/.git" ]; then
            warn "roll back with: git -C $INSTALL_DIR checkout <previous commit>"
        fi
        exit "$EXIT_FAIL"
    fi
    ok "now at version $(installed_version "$INSTALL_DIR")"
    if [ -f "$INSTALL_DIR/config.ini" ]; then
        action "re-check the install against the live server: bash setup.sh verify"
        info "the schedule was not touched; the next cron run uses the new files."
    fi
}

# ============================================================ menu / TUI ====
#
# A pointer-driven menu -- the front door for an operator who does not know
# the verbs. Each choice re-invokes THIS script with the matching verb as a
# fresh child process, so an action's exit and traps stay inside that child.
# Rendering goes through tput, so it is correct under tmux; with no
# interactive terminal, or a dumb TERM, it drops to a numbered prompt.

TUI_ANSI=0
tui_caps() {
    TUI_ANSI=0
    [ -t 0 ] && [ -t 1 ] || return 0
    case "${TERM:-dumb}" in dumb|'') return 0 ;; esac
    command -v tput >/dev/null 2>&1 || return 0
    tput sgr0 >/dev/null 2>&1 && tput bold >/dev/null 2>&1 && TUI_ANSI=1
    return 0
}
_t() { [ "$TUI_ANSI" = 1 ] && tput "$@" 2>/dev/null; return 0; }

MENU_LABELS=(); MENU_HINTS=(); MENU_VERBS=()
MENU_BUILDER="_menu_build"
MENU_TITLE=""
_menu_add() { MENU_LABELS+=("$1"); MENU_HINTS+=("$2"); MENU_VERBS+=("$3"); }
_menu_build() {
    MENU_LABELS=(); MENU_HINTS=(); MENU_VERBS=()
    _menu_add "Configure"  "connection, firewall pairs, policies, filters, email" configure
    _menu_add "Verify"     "read-only checks; render to out/, send nothing"      verify
    _menu_add "Run now"    "compare and email the real recipients (asks first)"  run
    _menu_add "Schedule"   "install or replace the cron entry"                   schedule
    _menu_add "Unschedule" "remove the cron entry, leaving files alone"          unschedule
    _menu_add "Status"     "configuration, schedule and last findings"           status
    _menu_add "Pairs"      "add, modify or remove a firewall pair; its recipients" pairs
    _menu_add "Update"     "fetch the newest release; keeps config, secrets, state" update
    _menu_add "Full setup" "configure, verify, then schedule in one pass"        install
    _menu_add "Uninstall"  "remove the schedule and, optionally, the files"      uninstall
}
# The Pairs sub-menu: one pair at a time, without redoing the wizard.
_menu_build_pairs() {
    MENU_LABELS=(); MENU_HINTS=(); MENU_VERBS=()
    _menu_add "List pairs"    "every pair, its devices, recipients and send rule"   list-pairs
    _menu_add "Add pair"      "two firewalls, who gets the report and when"        add-pair
    _menu_add "Modify pair"   "change devices, policies, recipients or send rule"  edit-pair
    _menu_add "Remove pair"   "drop a pair and its last-run state"                 remove-pair
    _menu_add "Add recipient" "add an email to one, several, or every pair"        add-recipient
}

_menu_status_line() {
    local parts=() p line="" v
    v="$(installed_version "$INSTALL_DIR")"
    [ -n "$v" ] && parts+=("v$v")
    if [ -f "$INSTALL_DIR/config.ini" ] && [ -f "$INSTALL_DIR/secrets.env" ]; then
        parts+=("configured")
    else
        parts+=("not configured")
    fi
    if have crontab; then
        local ct dline; ct="$(crontab -l 2>/dev/null || true)"
        if printf '%s\n' "$ct" | grep -qxF "$MARK_OPEN"; then
            dline="$(printf '%s\n' "$ct" | grep 'run_drift\.py' | head -n 1)"
            case "$dline" in
                *--dry-run*) parts+=("scheduled (dry-run)") ;;
                *)           parts+=("scheduled (LIVE)") ;;
            esac
        else
            parts+=("not scheduled")
        fi
    fi
    for p in "${parts[@]}"; do line="${line:+$line  ·  }$p"; done
    printf '%s' "$line"
}

_menu_draw() {
    local sel="$1" n="${#MENU_LABELS[@]}" i label hint
    _t clear
    _t civis
    _t bold; _t setaf 6
    printf '  FireMon Policy Drift Report%s\n' "${MENU_TITLE:+ -- $MENU_TITLE}"
    _t sgr0
    _t setaf 4; printf '  %s\n' "$(_menu_status_line)"; _t sgr0
    printf '  %s\n\n' "$INSTALL_DIR"
    for ((i = 0; i < n; i++)); do
        label="${MENU_LABELS[$i]}"; hint="${MENU_HINTS[$i]}"
        if [ "$i" = "$sel" ]; then
            _t bold; _t rev
            printf '> %d) %-14s %-55s' "$((i + 1))" "$label" "$hint"
            _t sgr0; printf '\n'
        else
            printf '  %d) %-14s %s\n' "$((i + 1))" "$label" "$hint"
        fi
    done
    printf '\n'
    _t setaf 4
    printf '  Up/Down or a number to choose  ·  Enter to run  ·  q to %s\n' "${MENU_TITLE:+go back}"
    [ -n "$MENU_TITLE" ] || printf '\033[1A  Up/Down or a number to choose  ·  Enter to run  ·  q to quit\n'
    _t sgr0
}

_menu_read() {
    local k seq
    IFS= read -rsn1 k </dev/tty 2>/dev/null || { printf 'QUIT'; return; }
    case "$k" in
        $'\e')
            seq=''
            read -rsn32 -t 0.06 seq </dev/tty 2>/dev/null || true
            case "$seq" in
                '[A'*|'OA'*)           printf 'UP' ;;
                '[B'*|'OB'*)           printf 'DOWN' ;;
                '['*';'*A*|'O'*';'*A*) printf 'UP' ;;
                '['*';'*B*|'O'*';'*B*) printf 'DOWN' ;;
                *)                     printf '' ;;
            esac ;;
        ''|$'\n'|$'\r') printf 'ENTER' ;;
        k|K) printf 'UP' ;;
        j|J) printf 'DOWN' ;;
        q|Q) printf 'QUIT' ;;
        [0-9]) printf '%s' "$k" ;;
        *) printf '' ;;
    esac
}

_menu_cleanup() { _t cnorm; _t sgr0; stty echo </dev/tty 2>/dev/null || true; }

_menu_dispatch() {
    local i="$1" verb
    verb="${MENU_VERBS[$i]}"
    _menu_cleanup
    _t clear
    _t bold; printf '=== %s ===\n\n' "${MENU_LABELS[$i]}"; _t sgr0
    bash "$SCRIPT_PATH" --dir "$INSTALL_DIR" "$verb"
    printf '\n'
    _t setaf 4; printf 'Press Enter to return to the menu.'; _t sgr0
    IFS= read -r _ </dev/tty 2>/dev/null || true
}

_menu_plain() {
    if ! { [ -t 0 ] && [ -t 1 ]; }; then
        usage
        return 0
    fi
    "$MENU_BUILDER"
    local n="${#MENU_LABELS[@]}" choice i
    while true; do
        printf '\nFireMon Policy Drift Report%s  --  %s\n' "${MENU_TITLE:+ -- $MENU_TITLE}" "$(_menu_status_line)"
        printf '  %s\n' "$INSTALL_DIR"
        for ((i = 0; i < n; i++)); do
            printf '  %d) %-14s %s\n' "$((i + 1))" "${MENU_LABELS[$i]}" "${MENU_HINTS[$i]}"
        done
        printf '  q) %s\n' "${MENU_TITLE:+Back}"
        [ -n "$MENU_TITLE" ] || printf '\033[1A  q) Quit\n'
        read -r -p 'Choose: ' choice </dev/tty || break
        case "$choice" in
            q|Q|'') break ;;
            *[!0-9]*) printf 'Enter a number, or q.\n' ;;
            *)
                i=$((10#$choice - 1))
                if [ "$i" -ge 0 ] && [ "$i" -lt "$n" ]; then
                    bash "$SCRIPT_PATH" --dir "$INSTALL_DIR" "${MENU_VERBS[$i]}"
                    printf '\nPress Enter to continue.'
                    IFS= read -r _ </dev/tty 2>/dev/null || break
                else
                    printf 'Choose 1-%d, or q.\n' "$n"
                fi ;;
        esac
    done
}

do_menu() {
    tui_caps
    if [ "$TUI_ANSI" != 1 ]; then
        _menu_plain
        return 0
    fi
    "$MENU_BUILDER"
    local sel=0 n="${#MENU_LABELS[@]}" key idx
    trap '_menu_cleanup' EXIT
    trap '_menu_cleanup; exit 130' INT
    trap '_menu_cleanup; exit 129' HUP
    trap '_menu_cleanup; exit 131' QUIT
    while true; do
        _menu_draw "$sel"
        key="$(_menu_read)"
        case "$key" in
            UP)    sel=$(( (sel - 1 + n) % n )) ;;
            DOWN)  sel=$(( (sel + 1) % n )) ;;
            ENTER) _menu_dispatch "$sel" ;;
            QUIT)  break ;;
            [0-9])
                idx=$((key - 1))
                if [ "$idx" -ge 0 ] && [ "$idx" -lt "$n" ]; then
                    sel="$idx"; _menu_dispatch "$sel"
                fi ;;
        esac
    done
    _menu_cleanup
    trap - EXIT INT HUP QUIT
    _t clear
}

# ---------------------------------------------------------------- main ------

# tests/test_setup.sh sources this file to exercise the config patcher, the
# crontab block surgery and the quoting. Sourcing stops here.
if [ "${FMDRIFT_SETUP_LIB-}" = "1" ]; then
    return 0
fi

while [ $# -gt 0 ]; do
    case "$1" in
        menu|install|configure|verify|run|schedule|unschedule|status|pairs|list-pairs|add-pair|edit-pair|remove-pair|add-recipient|restore-crontab|update|uninstall|help)
            if [ -z "$VERB" ]; then VERB="$1"; else POSITIONAL_ARG="$1"; fi ;;
        --dir)            INSTALL_DIR="$(cd "$2" 2>/dev/null && pwd)" || die "no such directory: $2"; shift ;;
        --at)             CRON_SPEC="$2"; VERB_FLAGS+=("--at"); shift ;;
        --live)           OPT_LIVE=1; VERB_FLAGS+=("--live") ;;
        --mail-proven)    OPT_MAIL_PROVEN=1; VERB_FLAGS+=("--mail-proven") ;;
        --with-logrotate) OPT_LOGROTATE=1; VERB_FLAGS+=("--with-logrotate") ;;
        --no-logrotate)   OPT_LOGROTATE=0; VERB_FLAGS+=("--no-logrotate") ;;
        --adopt)          OPT_ADOPT=1; VERB_FLAGS+=("--adopt") ;;
        --yes|-y)         OPT_YES=1; VERB_FLAGS+=("--yes") ;;
        --send-test)      OPT_SEND_TEST="$2"; VERB_FLAGS+=("--send-test"); shift ;;
        --pair)           PAIRS+=("$2"); VERB_FLAGS+=("--pair"); shift ;;
        --source)         OPT_SOURCE="$2"; VERB_FLAGS+=("--source"); shift ;;
        --check)          OPT_CHECK=1; VERB_FLAGS+=("--check") ;;
        --help|-h)        VERB="help" ;;
        -*)               die "unknown option: $1. Try: bash setup.sh help" ;;
        *)                POSITIONAL_ARG="$1" ;;
    esac
    shift
done

VERB="${VERB:-menu}"

if [ "$VERB" = "menu" ] && [ "${#VERB_FLAGS[@]}" -gt 0 ]; then
    die "these options apply to a verb, not the menu: ${VERB_FLAGS[*]}
         Run the verb directly, e.g.:  bash setup.sh run --send-test you@example.com"
fi

if [ "$VERB" = "schedule" ] || [ "$VERB" = "install" ]; then
    read -r -a _spec <<< "$CRON_SPEC"
    [ "${#_spec[@]}" -eq 5 ] || die "--at needs five cron fields (got '$CRON_SPEC')."
    case "$CRON_SPEC" in *%*) die "--at may not contain '%' -- cron treats it as a newline in the command." ;; esac
fi

case "$VERB" in
    help)            usage ;;
    menu)            do_menu ;;
    status)          do_status ;;
    configure)       do_configure ;;
    verify)          do_verify ;;
    run)             do_run ;;
    schedule)        do_schedule ;;
    unschedule)      do_unschedule ;;
    add-recipient)   do_add_recipient ;;
    pairs)           do_pairs_menu ;;
    list-pairs)      do_list_pairs ;;
    add-pair)        do_add_pair ;;
    edit-pair)       do_edit_pair ;;
    remove-pair)     do_remove_pair ;;
    restore-crontab) do_restore_crontab ;;
    update)          do_update ;;
    uninstall)       do_uninstall ;;
    install)
        do_configure
        do_verify
        head2 "Schedule it?"
        if confirm "Install the cron entry now ($CRON_SPEC)?"; then
            do_schedule
        else
            skip "not scheduled. When you are ready: bash setup.sh schedule"
        fi
        head2 "Done"
        info "status:   bash setup.sh status"
        info "re-check: bash setup.sh verify"
        ;;
    *) die "unknown verb: $VERB" ;;
esac
