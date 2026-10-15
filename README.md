# FireMon Policy Drift Report

Checks whether the security rules of two firewalls held in FireMon Security
Manager currently match, and reports where they do not:

1. rules that exist on firewall A but not on firewall B;
2. rules that exist on B but not on A;
3. rules present on both whose source, destination, service, application,
   zones, action, logging or other criteria differ — field by field, with
   what was added and what was removed.

This is a **convergence check, not a change log.** The two cluster members
are expected to be edited independently and can legitimately diverge
mid-cycle; a rule differing today and matching again tomorrow is not a
problem to chase. What matters is whether the primary and secondary end up
with the same security rules — so the report is built around current state
(what differs right now), not around the fact that something changed.

The comparison can be narrowed to a subset of rules — a category, a change
request number, an application, any rule-documentation property — and the
result is emailed, with a CSV of every finding attached. One install watches
any number of pairs, each with its own recipients, filters and send rule.
Built for the primary / disaster-recovery case (FMC-managed Firepower
policies that are meant to mirror each other), but nothing in it is
Firepower-specific.

## Why this exists

Two policies that are supposed to match rarely stay that way. A change lands
on the primary and not the DR site; an object is edited on one side; a rule
is disabled during testing and never re-enabled. Finding that by hand means
exporting both policies and comparing them in a spreadsheet, so it happens
before an audit and not otherwise. This runs the comparison on a schedule and
mails whatever currently does not match — not a history of every edit either
side has made, since edits that reconverge on their own are not drift.

## Requirements

Designed to run **directly on the FireMon appliance as an ordinary user** —
no root, no sudo, nothing installed outside your home directory. It runs fine
from a workstation too; the only difference is which host reaches the API and
the mail relay.

- Python **3.7 or newer**. Standard library only — no `pip install`. On FMOS
  the default `python3` may be **3.6**; `run_drift.py` and `run_tests.py`
  detect that and re-execute under the newest installed interpreter, so the
  commands below work as written.
- Access to the FireMon Security Manager API. On the appliance that is
  `https://localhost`.
- A way to schedule it. On FMOS that is your **user crontab**.
- An SMTP relay, if you want email. On the appliance, postfix is typically
  already listening on `127.0.0.1:25`.
- A FireMon account that can read the devices' rules, with its password
  supplied via `FMDRIFT_PASSWORD`.

`DEPLOYMENT.md` covers installation, scheduling and the FMOS specifics.

## Quick start

Run the setup script with no arguments and you get a menu — the front door:

```bash
cd ~/firemon-drift
bash setup.sh
```

```
  FireMon Policy Drift Report
  not configured  ·  not scheduled
  /home/you/firemon-drift

> 1) Configure   connection, firewall pairs, policies, filters, email
  2) Verify      read-only checks; render to out/, send nothing
  3) Run now     compare and email the real recipients (asks first)
  4) Schedule    install or replace the cron entry
  5) Unschedule  remove the cron entry, leaving files alone
  6) Status      configuration, schedule and last findings
  7) Add recipient  add an email to one, several, or every pair
  8) Update      fetch the newest release; keeps config, secrets, state
  9) Full setup  configure, verify, then schedule in one pass
 10) Uninstall   remove the schedule and, optionally, the files

  Up/Down or a number to choose  ·  Enter to run  ·  q to quit
```

The code lives at <https://github.com/adamgunderson/FireMon-Policy-Drift>:

```bash
git clone https://github.com/adamgunderson/FireMon-Policy-Drift.git ~/firemon-drift
# or, with no git on the box:
curl -fsSL https://github.com/adamgunderson/FireMon-Policy-Drift/archive/refs/heads/main.tar.gz | tar -xz
mv FireMon-Policy-Drift-main ~/firemon-drift
```

Pick **Full setup** for the first-time flow. It asks for the FireMon
connection, then for each pair: **lists the firewall devices** so you can
pick the two by name, **lists the policies on each** so you can pair them,
asks which rules to cover (every rule, or a category / change request /
application), who gets that pair's email and when — then "add another
pair?". Finally the mail relay. It writes `config.ini` and `secrets.env`,
proves them with a dry-run comparison of every pair against the live server,
and offers to schedule. Re-running it offers to keep the pairs you already
have and add more.

Every menu item is also a verb, so nothing needs the menu:

```bash
bash setup.sh configure     # or verify / run / schedule / status / ...
bash setup.sh help          # every verb, option and environment variable
```

**To add someone after setup has already run** — a manager who wants
visibility, say — without redoing the wizard:

```bash
bash setup.sh add-recipient boss@example.com                  # asks which pair(s), default "all"
bash setup.sh add-recipient boss@example.com --pair us-dr     # just that one (repeatable)
```

It patches only the `recipients` line(s) of the pair(s) you choose — nothing
else in `config.ini` changes — backs up the file first, and confirms the
edit still loads before calling it done. If the pair had no recipients
before (so `send_when` was auto-set to `never`), it offers to turn sending
back on right there.

To do it by hand instead:

```bash
cd ~/firemon-drift
cp config.example.ini config.ini && chmod 600 config.ini
vi config.ini                       # base_url, username, [pair:NAME] sections, [smtp]
export FMDRIFT_PASSWORD='...'

python3 run_tests.py                                     # code health; no network
python3 run_drift.py --config config.ini --list-devices FTDV   # find the device names
python3 run_drift.py --config config.ini --list-pairs          # what is configured
python3 run_drift.py --config config.ini --list-policies       # policy names, per pair
python3 run_drift.py --config config.ini --list-properties     # categories and properties in use
python3 run_drift.py --config config.ini --dry-run --print     # every report, on screen and in out/
python3 run_drift.py --config config.ini --pair us-dr --to-override you@example.com   # one pair, to you
python3 run_drift.py --config config.ini                       # live: every pair
```

## What a run does

Authenticates once, then for each configured pair (or those named with
`--pair`):

1. Resolves the two devices by name, and notes the date of each device's
   current configuration in FireMon (the "as of" the report quotes — this
   compares what FireMon has retrieved, not the firewalls directly).
2. Fetches every security rule in the paired policies from each device
   through the SIQL rule search: policy, objects (groups expanded), zones,
   action, logging, comment.
3. If a filter or a compared field needs rule documentation (change
   request, application, or any custom property), fetches each rule's
   rule-doc — one small call per rule; about 25 seconds for 2,200 rules on
   the appliance. The category is read from the rule comment where FMC
   wrote it (`cat:NAME;`), and the rule-doc is fetched only for the rules
   whose comment carries none, so the category column and comparison are
   right at a fraction of the cost.
4. Matches rules within each policy pair — **by name**, or by the vendor's
   own rule id for an HA pair or two devices that carry the same policy
   (`match_by`) — applies the filter, and compares the configured fields.
5. Marks which findings are new since the last live run, and which previous
   findings have resolved.
6. Renders that pair's report (HTML + plain text + CSV), sends it to that
   pair's recipients if its `send_when` allows, and records the findings as
   that pair's baseline for the next run.

If the two configurations FireMon holds were retrieved more than
`max_revision_skew_hours` apart (a day, by default), the report, its subject
and the console all say so, because a difference between a six-week-old
snapshot of one member and today's snapshot of the other is retrieval lag,
not drift. Fix the retrieval, then rerun.

A pair that fails — a device renamed, say — is reported and the other pairs
still run. Exit code `0` means no drift on any pair, `3` drift on at least
one, `1` a failure, `2` compared but an email could not be sent. A monitor
can alert on `3` directly.

## Configuration

`config.example.ini` is fully annotated; the settings that shape the
comparison are:

**`[pair:NAME]`** — one section per firewall pair. `primary` and
`secondary` (by name or id) are required; the primary is the reference.
Everything else is optional and, when left out, comes from the global
`[policies]`, `[filter]`, `[property_filters]`, `[compare]` and `[email]`
sections — so pairs that behave alike need only the two device names, and
`all` / `none` switches a global value off for one pair. Each pair keeps its
own last-run state and sends its own email.

```ini
[pair:us-dr]
primary         = USE-FW-FTDV-01
secondary       = USW-FW-FTDV-01
policies        = AZURE USE Transit = AZURE USW Transit, KF-CLOUD-PREFILTER
categories      = ESO*, SECURITY
recipients      = netops-us@example.com, dr-team@example.com
send_when       = changes

[pair:apac-dr]
primary    = APE1-FW-FTDV-01
secondary  = APSE2-FW-FTDV-01
recipients = netops-apac@example.com
```

A plain `[pair]` section with the two devices filled in is the single-pair
shorthand (a pair named `default`). `[policies:NAME]`,
`[property_filters:NAME]` and `[normalise:NAME]` sections scope those
settings to one pair when the one-line form is not enough. `--list-pairs`
prints the resolved configuration of every pair.

**`[policies]`** — which policy on the primary is compared with which on the
secondary, as `primary policy = secondary policy` lines. Rules are matched by
name *within* each pair, so a rule name reused across two policies does not
collide. Leave the section empty to compare every rule on each device across
all its policies. Per pair, the same thing on one line: `policies = A = B, C`.

```ini
[policies]
AZURE USE Transit  = AZURE USW Transit
KF-CLOUD-PREFILTER = KF-CLOUD-PREFILTER
```

**`[compare] fields`** — what counts as drift. The default is everything
except comment text, rule position and policy name. Rule position is
excluded because two policies that ever diverged and then converged keep
different positions forever; add `order` if position matters to you.
Comments are documentation, not policy. Any rule-doc property can be
compared too, as `prop:Business Owner`.

**`[compare] object_mode`** — how objects are compared:

| Mode | Two objects are equal when | Use it when |
|---|---|---|
| `name` (default) | their names match | both firewalls share an object store — the same FMC |
| `contents` | they resolve to the same addresses / ports, whatever they are called | separate managers; also catches an object with the same name but different members |
| `both` | name and contents both match | you want either kind of difference reported |

**`[compare] match_by`** — how a rule on one side is paired with a rule on
the other:

| Mode | Rules are the same rule when | Use it when |
|---|---|---|
| `name` (default) | their names match (after `[normalise]`) | the two policies are different policies that mirror each other — primary and DR sites with their own access control policies |
| `vendor_id` | the vendor's own rule id matches — the FMC rule UUID on Firepower | both firewalls carry the **same** policy from the same manager: an HA pair, or two devices assigned one access control policy. A renamed rule is then reported as a rename (a `Rule name` difference) instead of one rule missing and one extra. A rule with no vendor id falls back to its name. |

Across two different policies the vendor ids never match, so `vendor_id`
would report every rule as missing on both sides; the mode is per pair, so
an HA pair and a cross-site pair can sit in one config.

**`[compare] max_revision_skew_hours`** — how far apart the two sides'
"configuration as of" dates may be before the report warns that its findings
may be retrieval lag rather than drift. Default 24; 0 turns the check off.

**`[normalise]`** — regex substitutions applied to rule, object and zone
names on both sides before matching. Sites that mirror each other often name
things by site (`KF-USE-PROD-VNET` / `KF-USW-PROD-VNET`); compared literally
every such rule is drift. Fold the token away:

```ini
[normalise]
site_east = (?i)\bUSE\b => SITE
site_west = (?i)\bUSW\b => SITE
```

The raw names are still what the report shows.

**`[filter]`** — which rules the comparison covers:

```ini
[filter]
categories      = ESO*, SECURITY        ; FMC access-control category (glob)
change_requests = CHG0060157            ; substring of the CR property or the comment
applications    = Cisco Umbrella        ; Application Name property, or an application object
rule_names      = ALLOW_*               ; glob on the rule name

[property_filters]
Business Owner = netops@example.com     ; any rule-doc property
```

A rule is in scope when it matches every criterion set (AND across
criteria; OR within a list). **A rule is in scope when either side
matches**, so a rule whose category was changed on one site still appears —
as a category difference — rather than dropping out of one side and being
reported as missing. `--list-properties` prints the categories and property
values actually in use, with counts, to choose from.

Every filter has a command-line twin for ad-hoc runs: `--category`, `--cr`,
`--application`, `--rule-name`, `--property NAME=GLOB`, `--policy A=B`,
`--fields`, `--object-mode`, `--match-by`. Command-line values replace the config's on
every pair the run covers; `--primary X --secondary Y` compares an ad-hoc
pair that is not in the config at all.

**`[email]`** — default recipients and `send_when`, overridable per pair:
`drift` (only when differences exist — the default), `always` (a
heartbeat), `changes` (only when something is new or resolved since the
last live run), `never`.

## The report

A summary — rules retrieved and in scope per side, configuration dates,
matched / identical / differ / only-on-each counts, new and resolved since
last run — then three sections. The count rows link to their section, and
every firewall name links to its device page in Security Manager, and
every rule name to a rule search by that name across the domain, which
shows the rule on both firewalls side by side:

- **Rules that differ** — per rule, one row per differing field, the
  primary's value beside the secondary's. For object lists, one item per
  line: an item that firewall alone has is highlighted, the rest are grey.
- **Only on the primary** and **only on the secondary** — rule, policy,
  position, action, category and a one-line source → destination : service.
- **Resolved since last run** — differences reported last time that no
  longer exist.

Everything the tables truncate is in the attached CSV (one row per finding,
per field), and `attach_json = true` adds a machine-readable copy. `max_rows`
and `max_diff_rules` cap the email body because Gmail clips HTML over
~102 KB; the CSV is never capped.

### New and resolved

The state directory holds the fingerprints of what the last **live** run
reported, one small file per configured pair. Dry runs leave it alone, so a
rehearsal never consumes the NEW markers the scheduled run should show. Lose
the file and you lose one run's worth of NEW markers, nothing else. A first
run flags nothing as new — a report that shouts NEW at every line says
nothing.

## Command line

```
--config PATH         path to config.ini (required)
--dry-run             render to output_dir, send nothing, leave the state alone
--print               print the plain-text report to stdout
--to-override ADDR    send to ADDR instead of the configured recipients
--send-when MODE      override [email] send_when for this run
--json PATH           also write the findings as JSON
--update-state        record this run as the baseline even under --dry-run

--primary / --secondary DEVICE    override [pair]
--policy A[=B]        compare policy A with B (repeatable); --all-policies to ignore [policies]
--category GLOB       --cr TEXT   --application GLOB   --rule-name GLOB   --property NAME=GLOB
--fields LIST         --object-mode name|contents|both   --match-by name|vendor_id
--exclude-disabled

--list-devices [PATTERN]   firewall devices, to find names for [pair]
--list-policies            the policies on each device, to fill [policies]
--list-properties          categories and rule-doc properties in use, with counts
--no-csv  --log-level LEVEL  --version
```

## Running it on a schedule

`setup.sh schedule` installs a cron entry (daily at 06:00 by default;
`--at "0 7 * * 1"` for weekly). It schedules with `--dry-run` until you pass
`--live --mail-proven`, which asserts you have run a live send and found
`mailq` empty afterwards. Before writing the crontab it backs up what was
there, rehearses the exact command in a cron-like environment, edits only
between its own markers, reads the result back, and restores the backup if
that does not match. See `DEPLOYMENT.md`.

## Design notes

**Rules are matched by name, or by vendor id.** Across two different
policies the name is the only identifier they share: FireMon's rule ids and
the vendor's UUIDs differ per policy, so a rule renamed on one side reads as
missing on that side and extra on the other, which is the honest description.
When both firewalls carry the *same* policy (an HA pair), the vendor's rule
id is shared and `match_by = vendor_id` pairs rules by it, so a rename is
reported as a rename. A duplicate key within one policy is logged and only
the first occurrence is compared.

**The report says when the two snapshots are not contemporaneous.** FireMon
retrieves each member of a pair on its own schedule; if one retrieval failed
for weeks, the comparison is between two different points in time and every
"finding" is lag. The report compares the two configuration dates and, past
`max_revision_skew_hours`, warns in the subject, at the top of the body and
on the console, naming the side whose configuration is stale.

**Filters scope by either side.** See `[filter]` above. The alternative —
filter each side independently, then compare — silently converts "the
category was changed on the DR site" into "the rule is missing on the DR
site", which is wrong in both directions.

**Comparison is against FireMon's copy, not the firewall.** The report
quotes the retrieval date of each device's current revision so a difference
can be checked against the change log before anyone is paged.

**Nothing is stored except fingerprints.** The findings are recomputed from
the firewalls every run; the state file only lets the next run say what is
new. There is no database to back up and nothing to go stale.

## Updating

```bash
bash setup.sh update --check    # is a newer version available? changes nothing
bash setup.sh update            # fetch it and swap the program files in
bash setup.sh update --source /tmp/FireMon-Policy-Drift-main.tar.gz   # from a file on the box
```

Also the **Update** item on the menu. It replaces only the program files —
`firemon_drift/`, `templates/`, `tests/`, the two `run_*.py`, `setup.sh`,
`config.example.ini` and the docs — and leaves `config.ini`, `secrets.env`,
`state/`, `out/`, `backups/`, the logs and the crontab exactly as they are.
The files it replaces are archived to `backups/code-<timestamp>.tar.gz`
first; the unit tests then run on the result and a failure puts the
previous files back. An install that is a git clone is updated with
`git pull --ff-only` instead. On an appliance with no route to GitHub,
download the tarball elsewhere and pass it with `--source`. Each file is
swapped in by rename, so updating `setup.sh` from inside `setup.sh` is safe.
`status` shows the installed version.

## Tests

```bash
python3 run_tests.py          # unit tests: flattening, comparison, filters, rendering, config, state
bash tests/test_setup.sh      # the installer: config patching, [policies] writer, crontab surgery, quoting
```

Both run without a network, against synthetic rules. Nothing in the test
fixtures is customer data.
