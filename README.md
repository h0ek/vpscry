# VPScry

**See what your VPS is hiding.**

VPScry is a read-only health and security auditor for Debian 12 and Debian 13 VPS hosts.

It inspects the local system, correlates configuration with runtime state, highlights security and operational issues, and writes detailed reports. It does not automatically change the server.

VPScry combines “VPS” with “scry” — to look closely and reveal what is normally hidden.

## What it checks

VPScry covers:

- system health, disk, inodes, memory, time and reboot state;
- systemd services, custom units, execution paths and service hardening;
- network interfaces, listeners, firewall rules, routing, DNS and expected ports;
- SSH, local accounts, sudo, password policy and permissions;
- APT, unattended-upgrades, journald, logrotate, cron and scheduled jobs;
- Nginx, Apache, PHP-FPM, Certbot, PM2 and TLS;
- PostgreSQL, MariaDB/MySQL, Redis, MongoDB, Memcached and Elasticsearch/OpenSearch;
- Docker and Podman;
- backups and retention indicators;
- sysctl, mounts, SUID/SGID, ACLs, AppArmor, Fail2ban, CrowdSec and auditd;
- Tor, WireGuard, OpenVPN, Tailscale, strongSwan, cloud-init and VPS virtualization context.

Optional components that are not installed are treated as neutral, not as passed checks.

## Requirements

- Debian 12 or Debian 13
- Bash
- standard Debian command-line tools, including GNU coreutils (`sha256sum`, `mktemp`, `realpath`)
- root privileges recommended for a complete audit

No installation is required.

## Usage

```bash
chmod +x vpscry.sh
sudo ./vpscry.sh
```

For a public VPS, define the ports that are intentionally reachable:

```bash
sudo ./vpscry.sh \
  --expected-ports tcp:22,tcp:80,tcp:443
```

Do not add loopback-only application ports to `--expected-ports`.

## Reports

By default VPScry creates:

```text
./vpscry-HOST-YYYYMMDD-HHMMSS/
```

with:

```text
report-actions.txt   FAIL and WARN findings only
report.txt           complete text report
report.md            complete Markdown report
report.json          structured JSON
report.html          standalone HTML
```

SARIF is optional.

Report files use mode `0600`; newly created report directories use `0700`. Existing directory permissions and unrelated files are preserved. With `sudo`, created reports belong to the invoking user.

Reports and baselines are written through temporary files and replaced atomically per file. Output directories must belong to the caller or the invoking `sudo` user and must not be group/world-writable. Symlink output directories and symlink, hardlink or non-regular destination files are rejected. A write failure returns exit code `1`; files completed earlier in the run may already exist.

Reports can contain sensitive information about the host. Do not publish them without reviewing their contents.

## Online checks

VPScry is offline by default.

```bash
sudo ./vpscry.sh --online
```

Online mode permits optional clearnet DNS, HTTP and TLS checks for detected or configured public websites.

`.onion` names are not queried through public DNS.

VPScry does not upload reports or telemetry.

## Configuration file

Configuration is optional.

```bash
sudo ./vpscry.sh --config ./vpscry.conf.example
```

The file uses a data-only `key=value` format. It is parsed and never executed with `source` or `eval`.

Supported keys:

```text
expected_ports
expected_services
expected_websites
expected_timers
expected_backups
severity_profile
fail_on
evidence_limit
command_timeout
baseline_file
write_baseline_file
formats
output_dir
sarif
disk_warn_percent
disk_fail_percent
inode_warn_percent
inode_fail_percent
backup_max_age_days
log_growth_mib
redact_literal
suppress
```

`redact_literal` and `suppress` may be specified more than once.

`redact_literal` performs case-sensitive literal replacement in finding titles, evidence, verification commands, recommendations, suppression reasons and host metadata. It is not automatic secret detection.

Suppression format:

```text
suppress=FINDING-ID|YYYY-MM-DD|Reason
```

## Baselines

Create a reviewed baseline:

```bash
sudo ./vpscry.sh \
  --write-baseline /var/lib/vpscry/host.baseline
```

Compare a later audit with it:

```bash
sudo ./vpscry.sh \
  --baseline /var/lib/vpscry/host.baseline
```

Baselines compare finding IDs, statuses and SHA-256 hashes of stored evidence. Evidence is normalized, redacted and limited by `evidence_limit` before hashing. Legacy fingerprints support status comparison only and require a new reviewed baseline for evidence comparison.

## Command-line options

```text
--output-dir DIR
    Report directory.
    Default: ./vpscry-HOST-TIMESTAMP

--formats LIST
    Comma-separated output formats:
    text,markdown,json,html,actions,sarif,all
    Default: text,markdown,json,html,actions

--online
    Permit optional clearnet outbound checks.

--config FILE
    Load a VPScry data-only policy file.

--expected-ports LIST
    Expected public listeners.
    Example: tcp:22,tcp:80,tcp:443,udp:51820

--baseline FILE
    Compare this run with a VPScry baseline.

--write-baseline FILE
    Write a deterministic baseline snapshot.

--severity-profile PROFILE
    balanced, strict or relaxed

--evidence-limit N
    Maximum stored evidence length per finding.
    Range: 400-12000
    Default: 1600

--timeout N
    Maximum timeout for an individual command.
    Range: 2-300 seconds
    Default: 90

--sarif
    Also create report.sarif.

--fail-on LEVEL
    none, fail or warn
    Returns exit code 2 after writing reports when the selected threshold is met.

--no-color
    Disable terminal colors.

--verbose
    Print every finding and its evidence while scanning.

--quiet
    Print only the final summary.

--version
    Print the VPScry version.

-h, --help
    Show built-in help.
```

## Exit codes

```text
0    Audit completed
1    Invalid arguments or fatal runtime error
2    Audit completed and --fail-on threshold was met
130  Interrupted
```

## Safety

VPScry does not intentionally:

- modify system configuration or permissions;
- install, remove or update packages;
- restart or reload services;
- rotate or delete logs;
- execute backup, restore, renewal or application hooks;
- print secret values;
- upload reports or telemetry;
- make outbound connections unless `--online` is used.

VPScry is an auditing aid. Findings should be reviewed in the context of the actual server workload and network design.

Firewall analysis is conservative: unsupported rules, multiple input chains and unresolved chain traversal require manual review. A default drop policy alone does not prove effective protection. PostgreSQL HBA includes and ambiguous Tor instance configurations are marked as incomplete instead of passing authentication checks.

## Tests

The regression suite requires Python 3 and uses local fixtures without changing service configuration:

```bash
bash -n vpscry.sh
python3 -B -m unittest discover -s tests -v
```

GitHub Actions runs the suite on Debian 12 and Debian 13 containers.

## License

MIT
