# Deploying the drift report on FMOS

Written for running this **directly on a FireMon appliance, as an ordinary
user**. Verified on FMOS 2026.2.6 as an unprivileged account; other recent
FMOS releases behave the same way.

> **This is unmanaged software.** It is not part of FireMon and is not
> installed or upgraded by it. An FMOS upgrade can remove or break it.
> Re-verify after every appliance upgrade — see [After an FMOS upgrade](#after-an-fmos-upgrade).

---

## What the appliance actually provides

FMOS is RHEL based. Five things differ from a normal Linux host, and together
they decide the whole install shape.

| | What you get | Consequence |
|---|---|---|
| **No root, no sudo** | `sudo` is not installed. `/opt`, `/etc` and `/etc/systemd/system` are read-only to you. | **Install into your home directory.** Nothing in this guide needs privilege. |
| **Python** | `/usr/bin/python3` may be **3.6** — too old (no `dataclasses`). Newer interpreters (3.9, 3.12) are installed alongside. | Nothing to do. `run_drift.py` and `run_tests.py` re-execute under the newest interpreter, so plain `python3` commands work — including from cron. |
| **Scheduling** | System units need root. User units cannot be made to survive logout (no PolicyKit for `enable-linger`). | **Use your user crontab.** |
| **Mail** | **postfix is typically active on 127.0.0.1:25.** | No relay to configure for on-box use — but see [Prove mail actually leaves the box](#5-prove-mail-actually-leaves-the-box). |
| **API** | FireMon answers on `https://localhost`. | The report never leaves the appliance. TLS is self-signed, so `verify_tls = false` or supply a `ca_bundle`. |

Confirm on your own box before starting:

```bash
head -2 /etc/os-release
python3 --version                # 3.6.x is fine -- the tool re-executes
ls /usr/bin/python3.[0-9]*       # expect a 3.7+ among these
systemctl is-active postfix
crontab -l                       # "no crontab for <user>" is fine; the binary must exist
```

---

## Before you start

| What | Where it comes from | Notes |
|---|---|---|
| Device names | `run_drift.py --list-devices FTDV`, or the FireMon device list | exactly as FireMon shows them; ids work too |
| Policy names | `run_drift.py --list-policies` | the display names, e.g. `AZURE USE Transit` |
| Service account | FireMon admin | read access to the devices' rules and rule documentation |
| From address | your mail team | must be one the relay will accept |
| Outbound mail path | your mail team | whether this appliance may send externally at all |

The setup wizard fetches the first two for you.

---

## 1. Install

No privilege required. Pick an account that will still exist next year.

```bash
# with git and a route to GitHub:
git clone https://github.com/adamgunderson/FireMon-Policy-Drift.git ~/firemon-drift

# without git:
curl -fsSL https://github.com/adamgunderson/FireMon-Policy-Drift/archive/refs/heads/main.tar.gz | tar -xz
mv FireMon-Policy-Drift-main ~/firemon-drift

# with no route to the internet at all: fetch the tarball on a workstation,
# scp it to the appliance, unpack it the same way.

cd ~/firemon-drift
python3 run_tests.py            # code health; no network
bash tests/test_setup.sh        # the installer's own checks; no network
```

A git clone updates itself later with `git pull` (via `bash setup.sh
update`); a tarball install updates from the next tarball. Either works.

## The short way

```bash
bash setup.sh                   # the menu; choose "Full setup"
# or, without the menu:
bash setup.sh install
```

The wizard asks for the FireMon URL and credentials, then for each pair:
lists the firewall devices, asks for the primary and secondary and a name
for the pair, lists the policies on each and asks how to pair them, asks
which rules to cover, who gets that pair's email and when — and whether to
add another pair. Then the mail relay. It shows what it is about to write,
proves it with a dry-run comparison of every pair, then offers to schedule.
It writes `config.ini` (mode 0600, no passwords) and `secrets.env` (mode
0600, the passwords, sourced by the cron line), and leaves `backups/` and
`setup.log` behind. Re-running it offers to keep the pairs already in
`config.ini` and add more.

It can run unattended — every prompt has an environment variable
(`bash setup.sh help` lists them); pairs are numbered:

```bash
FMDRIFT_PASSWORD='...' FMDRIFT_SETUP_BASE_URL=https://localhost \
FMDRIFT_SETUP_DOMAIN_ID=1 FMDRIFT_SETUP_USERNAME=svc-drift FMDRIFT_SETUP_VERIFY_TLS=no \
FMDRIFT_SETUP_KEEP_PAIRS=no FMDRIFT_SETUP_PAIR_COUNT=2 FMDRIFT_SETUP_LIST_PROPERTIES=no \
FMDRIFT_SETUP_PAIR1_NAME=us-dr \
FMDRIFT_SETUP_PAIR1_PRIMARY=USE-FW-FTDV-01 FMDRIFT_SETUP_PAIR1_SECONDARY=USW-FW-FTDV-01 \
FMDRIFT_SETUP_PAIR1_POLICIES='AZURE USE Transit=AZURE USW Transit, KF-CLOUD-PREFILTER' \
FMDRIFT_SETUP_PAIR1_MATCH_BY=name FMDRIFT_SETUP_PAIR1_CATEGORIES=all FMDRIFT_SETUP_PAIR1_CHANGE_REQUESTS=none \
FMDRIFT_SETUP_PAIR1_APPLICATIONS=none \
FMDRIFT_SETUP_PAIR1_RECIPIENTS=netops-us@example.com FMDRIFT_SETUP_PAIR1_SEND_WHEN=changes \
FMDRIFT_SETUP_PAIR2_NAME=apac-dr \
FMDRIFT_SETUP_PAIR2_PRIMARY=APE1-FW-FTDV-01 FMDRIFT_SETUP_PAIR2_SECONDARY=APSE2-FW-FTDV-01 \
FMDRIFT_SETUP_PAIR2_POLICIES=all FMDRIFT_SETUP_PAIR2_MATCH_BY=name FMDRIFT_SETUP_PAIR2_CATEGORIES=all \
FMDRIFT_SETUP_PAIR2_CHANGE_REQUESTS=none FMDRIFT_SETUP_PAIR2_APPLICATIONS=none \
FMDRIFT_SETUP_PAIR2_RECIPIENTS=netops-apac@example.com FMDRIFT_SETUP_PAIR2_SEND_WHEN=drift \
FMDRIFT_SETUP_SMTP_HOST=localhost FMDRIFT_SETUP_FROM_ADDRESS=firemon-drift@example.com \
bash setup.sh configure --yes
```

## 2. Configure by hand

```bash
cp config.example.ini config.ini
chmod 600 config.ini
vi config.ini
```

The settings that matter: `[firemon] base_url` (`https://localhost` on the
box), `username`, `verify_tls = false`; one `[pair:NAME]` section per
firewall pair with `primary`, `secondary` and `recipients` (or a plain
`[pair]` for a single pair); `[smtp] from_address`. Use absolute paths in
`[paths]` once scheduled. `run_drift.py --list-pairs` shows how each pair
resolved.

### Keep credentials out of the config

```bash
cat > ~/firemon-drift/secrets.env <<'EOF'
export FMDRIFT_PASSWORD='the-service-account-password'
EOF
chmod 600 ~/firemon-drift/secrets.env
```

The environment always wins over the file, so `config.ini` can hold no
secret at all. The report warns if it finds one in a world-readable file.

## 3. Verify, before anything is sent

```bash
cd ~/firemon-drift && . secrets.env

# 1. Auth and device resolution, every pair. Read-only.
python3 run_drift.py --config config.ini --list-pairs
python3 run_drift.py --config config.ini --list-policies

# 2. What categories and properties exist, to choose filters. Read-only.
python3 run_drift.py --config config.ini --list-properties --pair us-dr

# 3. The comparison, rendered to out/ and printed. Sends nothing, records nothing.
python3 run_drift.py --config config.ini --dry-run --print

# 4. One real email per pair, all to yourself.
python3 run_drift.py --config config.ini --to-override you@example.com --send-when always

# 5. Confirm it actually left the box -- see section 5.
mailq | tail -5
```

Or `bash setup.sh verify` for 1–3 and the queue check in one pass, and
`bash setup.sh run --send-test you@example.com` for 4.

`out/drift-<run>.eml` is the complete message; copy it off the box and open
it in Outlook to see exactly what recipients will get.

## 4. Read the exit code

| Code | Meaning | Under cron |
|---|---|---|
| `0` | ran; no drift on any pair | quiet |
| `3` | ran; drift found on at least one pair | quiet — the email is the alert; a monitor may key on this |
| `1` | failed: config or auth, or a pair could not be compared (the others still ran) | investigate `cron.log` |
| `2` | compared, but an email could not be sent | check the ledger in `out/` and `mailq` |

## 5. Prove mail actually leaves the box

**The step most likely to be skipped, and most likely to matter.**

"accepted by the relay" means postfix *accepted* the message. That is the
last thing any SMTP client can observe. Always check the queue after a live
send:

```bash
mailq | tail -5      # anything listed is NOT delivered
```

A populated queue is often not this tool's doing: on many appliances it
holds FireMon's own notification emails, which means outbound mail was
already broken. The classic failures are the destination refusing the
connection (sending reputation — the appliance is not authorised to send as
that domain, and postfix commonly rewrites the sender via
`/etc/postfix/sender_canonical`) and a connection timeout (no route to the
destination's mail servers).

```bash
postconf -h relayhost myhostname sender_canonical_maps
cat /etc/postfix/sender_canonical 2>/dev/null
```

If mail cannot leave the appliance, in order of preference:

1. **Point postfix at an internal smarthost** (`relayhost`). Needs an
   administrator, and it repairs FireMon's own notifications too.
2. **Bypass postfix**: set `[smtp] host` / `port` to a relay that accepts
   authenticated submission, `use_starttls = true`, and the password in
   `FMDRIFT_SMTP_PASSWORD`. Needs no privilege.
3. **Do not schedule live mail yet.** Schedule with `--dry-run` (the
   default) and read `out/` instead.

## 6. Schedule with cron

`setup.sh schedule` installs the entry below between its own markers, having
first backed up your crontab and rehearsed the command, plus a monthly
log-trimming block (section 7). It refuses to schedule live mail without
`--live --mail-proven`.

```bash
bash setup.sh schedule                          # daily 06:00, --dry-run
bash setup.sh schedule --at "0 7 * * 1"         # weekly, Monday 07:00
bash setup.sh schedule --live --mail-proven     # after section 5
```

To do it by hand:

```cron
# FireMon policy drift report -- daily at 06:00
MAILTO=""
0 6 * * * . "$HOME/firemon-drift/secrets.env"; /usr/bin/python3 "$HOME/firemon-drift/run_drift.py" --config "$HOME/firemon-drift/config.ini" >> "$HOME/firemon-drift/cron.log" 2>&1
```

Absolute paths everywhere; source `secrets.env` first; `MAILTO=""` so cron
does not mail you the console summary every day (it lands in `cron.log`).

**Send only on change.** The default `send_when = drift` mails every run
that finds any difference, which for a pair with known, accepted differences
is every run. Two ways to make the mail mean something, both settable per
pair:

- `send_when = changes` — mail only when a finding is new or a previous one
  has resolved since the last live run.
- Narrow the pair's scope (`categories`, `change_requests`, `applications`)
  to the rules that are supposed to match, and keep `drift`.

One cron entry runs every pair; there is no need for one per pair.

## 7. Log rotation

Installed by default by `setup.sh schedule`; `--no-logrotate` to skip:

```cron
0 3 1 * * tail -n 2000 "$HOME/firemon-drift/cron.log" > "$HOME/firemon-drift/cron.log.tmp" && mv "$HOME/firemon-drift/cron.log.tmp" "$HOME/firemon-drift/cron.log"
0 3 1 * * find "$HOME/firemon-drift/out" -type f -mtime +90 -delete
```

`out/` holds one ledger per run plus any rendered reports. The `find`
deletes rendered reports and ledgers older than 90 days; `state/` (the
last-run baseline) is never touched.

## Adding a recipient later

Someone wants added — a manager, an auditor — after the pairs are already
configured and possibly scheduled. Nothing else needs to change:

```bash
bash setup.sh add-recipient boss@example.com                # asks which pair(s)
bash setup.sh add-recipient boss@example.com --pair us-dr    # or name them directly (repeatable)
```

It edits only the target pair's `recipients =` line (adding to what is
already there, deduped case-insensitively), backs up `config.ini` to
`backups/` first, and confirms with `run_drift.py --list-pairs` (no network
call, so this is fast) that the file still loads before it finishes —
restoring the backup automatically if it doesn't. If the pair had no
recipients before, its `send_when` was set to `never` by the wizard; adding
a recipient prompts to turn it back on so the new address is not silently
mailed nothing. Unattended: `FMDRIFT_SETUP_NEW_RECIPIENT` and
`FMDRIFT_SETUP_RECIPIENT_PAIRS` (`bash setup.sh help` has the full list).

To add, change or drop a whole pair — its two firewalls, how its rules are
matched, which policies, who gets its report and when — use the **Pairs**
menu or `bash setup.sh add-pair` / `edit-pair NAME` / `remove-pair NAME`.
Each works on a copy of `config.ini`, shows the diff, asks, backs up,
writes, proves the file still loads and offers a dry run of the pair.
Unattended, `add-pair` and `edit-pair` read the same `FMDRIFT_SETUP_PAIR1_*`
variables as the wizard, and `FMDRIFT_SETUP_TARGET_PAIR` names the pair to
edit or remove.

## Updating the tool

```bash
cd ~/firemon-drift
bash setup.sh update --check        # reports the installed and available versions
bash setup.sh update                # asks, then replaces the program files
```

Or choose **Update** from the menu. What it does, in order:

1. Fetches the release — `git pull --ff-only` for a clone; otherwise the
   tarball of `main` from GitHub, or whatever `--source` names (a directory,
   `.tar.gz` or `.zip` on the box, or a URL). Behind a proxy, set
   `https_proxy` as you would for curl.
2. Archives the files it is about to replace to `backups/code-<stamp>.tar.gz`.
3. Swaps in the new `firemon_drift/`, `templates/`, `tests/`, `run_drift.py`,
   `run_tests.py`, `setup.sh`, `config.example.ini` and the docs. Nothing
   else is touched: `config.ini`, `secrets.env`, `state/`, `out/`,
   `backups/`, the logs and the crontab stay as they are.
4. Runs the unit tests on the result. If they fail, the archived files are
   put back and the command exits 1.

Then `bash setup.sh verify` to prove the new code against the live server.
A new release may add settings to `config.example.ini`; they all have
defaults, so an existing `config.ini` keeps working — diff the two when you
want to adopt them. With no route to GitHub, download the tarball on a
workstation, copy it over, and run `bash setup.sh update --source
/path/to/main.tar.gz`. `FMDRIFT_UPDATE_REPO` and `FMDRIFT_UPDATE_REF` point
the default download at a fork or a tag.

## After an FMOS upgrade

```bash
cd ~/firemon-drift
python3 run_tests.py
bash setup.sh verify
bash setup.sh status
```

An upgrade can change which Python versions are installed (the bootstrap
copes), reset postfix, or — rarely — clear user crontabs. `status` shows
whether the managed block is still there; `backups/` holds every crontab the
installer ever replaced, and `bash setup.sh restore-crontab` puts one back.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `no device named '...'` | name differs from FireMon's, or wrong domain | `--list-devices <fragment>`; use the id if names are ambiguous |
| `no rules found in a policy named '...'` | policy display name mistyped | `--list-policies`; names are matched case-insensitively against both display name and vendor id |
| Every rule reported as different in `sources` / `destinations` | site-specific object names | add `[normalise]` substitutions, or `object_mode = contents` |
| Hundreds of "only on" findings | the policies genuinely differ that much | narrow with `[filter]`, or accept and use `send_when = changes` |
| Every rule "only on" both sides for an HA pair | `match_by = vendor_id` on two *different* policies | vendor ids are only shared within one policy; use `match_by = name` |
| A renamed rule shows as missing + extra | matched by name | for an HA pair or a shared policy, `match_by = vendor_id` |
| Subject says `[configs N days apart]` | FireMon has not retrieved one member for a while | fix the retrieval for the device it names; the findings are lag until then |
| `--list-properties` shows no properties | rule documentation empty, or the account cannot read it | filters on properties will match nothing; category still comes from the comment pattern |
| Email body clipped in Gmail | over ~102 KB | lower `max_rows` / `max_diff_rules`; the CSV has everything |
| `exit 3` under cron looks like an error | it is not | drift found; see section 4 |
| `secrets.env did not read back as written` | password contains something the installer cannot quote | export `FMDRIFT_PASSWORD` in the environment instead |
