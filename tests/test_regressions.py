import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "vpscry.sh"


class RegressionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="vpscry-tests-")
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def bash(self, code, timeout=20):
        env = dict(os.environ, VPSCRY_SCRIPT=str(SCRIPT), TEST_ROOT=str(self.root))
        env.pop("BASH_ENV", None)
        return subprocess.run(
            ["bash", "--noprofile", "--norc", "-c", '''
source "$VPSCRY_SCRIPT"
TERMINAL_MODE=quiet
REPORT_OWNER_UID=""
REPORT_OWNER_GID=""
TMP_DIR="$TEST_ROOT/tmp"
mkdir -m 700 -p "$TMP_DIR"
OUTPUT_DIR="$TEST_ROOT/reports"
''' + code],
            env=env, text=True, capture_output=True, timeout=timeout,
        )

    def success(self, code):
        result = self.bash(code)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        return result

    def findings(self, code):
        self.success(code + '\nwrite_json_report "$TEST_ROOT/result.json"\n')
        report = json.loads((self.root / "result.json").read_text())
        return {item["id"]: item for item in report["results"]}

    def test_literal_replacement_never_reprocesses_replacement(self):
        result = self.success('''
literal_replace 'REDACTED REDACTED' 'REDACTED' '[REDACTED]'
printf '\n'
literal_replace 'a*a [x] a*a' 'a*a' '[REDACTED]'
printf '\n'
literal_replace 'abc' '' 'x'
''')
        self.assertEqual(result.stdout, '[REDACTED] [REDACTED]\n[REDACTED] [x] [REDACTED]\nabc')

    def test_redaction_covers_reports_baseline_and_suppression(self):
        self.success('''
REDACT_LITERALS=('secret-host')
HOSTNAME_VALUE=secret-host
EXPECTED_PORTS_RAW=secret-host
SUPPRESS_UNTIL[TEST-SUPPRESSED]=2999-01-01
SUPPRESS_REASON[TEST-SUPPRESSED]='secret-host reason'
add_result TEST-SUPPRESSED test FAIL HIGH HIGH 'secret-host title' 'secret-host evidence' 'secret-host verify' 'secret-host fix'
add_result TEST-ACTIVE test FAIL HIGH HIGH 'secret-host title' 'secret-host evidence' 'secret-host verify' 'secret-host fix'
FORMATS=all
WRITE_BASELINE_FILE="$TEST_ROOT/host.baseline"
write_reports
''')
        for path in [*self.root.joinpath("reports").iterdir(), self.root / "host.baseline"]:
            with self.subTest(path=path.name):
                self.assertNotIn("secret-host", path.read_text())
                self.assertIn("[REDACTED]", path.read_text())

    def test_default_report_directory_uses_redacted_hostname(self):
        result = self.success('''
OUTPUT_DIR=""
HOSTNAME_VALUE=secret-host
REDACT_LITERALS=('secret-host')
parse_args
printf '%s' "$OUTPUT_DIR"
''')
        self.assertNotIn("secret-host", result.stdout)
        self.assertIn("REDACTED", result.stdout)

    def test_json_and_sarif_escape_every_representable_control_character(self):
        self.success(r'''
value='quote" backslash\ Unicode: żółć '
for ((i=1; i<32; i++)); do
    printf -v oct '%03o' "$i"
    printf -v ch '%b' "\\$oct"
    value+="$ch"
done
add_result TEST-CONTROLS test FAIL HIGH HIGH "$value" x x x
R_EVIDENCE[0]="$value"
HOSTNAME_VALUE="$value"
FORMATS=all
write_reports
json_escape "$value" > "$TEST_ROOT/escaped.txt"
''')
        expected = 'quote" backslash\\ Unicode: żółć ' + ''.join(map(chr, range(1, 32)))
        report = json.loads((self.root / "reports/report.json").read_text())
        sarif = json.loads((self.root / "reports/report.sarif").read_text())
        self.assertEqual(report["host"], expected)
        self.assertEqual(report["results"][0]["evidence"], expected)
        self.assertEqual(sarif["runs"][0]["results"][0]["properties"]["evidence"], expected)
        self.assertEqual(json.loads('"' + (self.root / "escaped.txt").read_text() + '"'), expected)

    def test_existing_unrelated_files_and_directory_keep_permissions(self):
        output = self.root / "reports"
        output.mkdir(mode=0o750)
        unrelated = output / "unrelated.txt"
        unrelated.write_text("keep me")
        unrelated.chmod(0o644)
        self.success('FORMATS=all\nwrite_reports')
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o750)
        self.assertEqual(stat.S_IMODE(unrelated.stat().st_mode), 0o644)
        self.assertEqual(unrelated.read_text(), "keep me")
        for path in output.glob("report*"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_new_report_directory_is_private(self):
        self.success('umask 022\nFORMATS=text\nwrite_reports')
        self.assertEqual(stat.S_IMODE((self.root / "reports").stat().st_mode), 0o700)

    def test_report_symlinks_hardlinks_and_special_files_are_rejected(self):
        output = self.root / "reports"
        output.mkdir()
        victim = self.root / "victim.txt"
        victim.write_text("do not modify")
        victim.chmod(0o644)
        target = output / "report.txt"
        for kind in ("symlink", "dangling", "hardlink", "directory", "fifo"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    target.symlink_to(victim)
                elif kind == "dangling":
                    target.symlink_to(self.root / "missing")
                elif kind == "hardlink":
                    os.link(victim, target)
                elif kind == "directory":
                    target.mkdir()
                else:
                    os.mkfifo(target)
                result = self.bash('FORMATS=text\nwrite_reports')
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(victim.read_text(), "do not modify")
                self.assertEqual(stat.S_IMODE(victim.stat().st_mode), 0o644)
                self.assertFalse((self.root / "missing").exists())
                if kind == "directory":
                    target.rmdir()
                else:
                    target.unlink()

    def test_output_symlink_is_rejected_with_trailing_slash(self):
        real = self.root / "real"
        real.mkdir()
        (self.root / "reports").symlink_to(real, target_is_directory=True)
        for suffix in ("", "/", "//"):
            result = self.bash(f'OUTPUT_DIR+="{suffix}"\nFORMATS=text\nwrite_reports')
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(list(real.iterdir()), [])

    def test_untrusted_output_directory_is_rejected(self):
        output = self.root / "reports"
        output.mkdir()
        output.chmod(0o777)
        result = self.bash('FORMATS=text\nwrite_reports')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o777)

    def test_failed_renderer_keeps_previous_report_and_returns_error(self):
        output = self.root / "reports"
        output.mkdir()
        (output / "report.json").write_text("previous report")
        result = self.bash('''
write_json_report() { printf partial > "$1"; return 1; }
FORMATS=json
write_reports
printf 'unexpected success'
''')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn("unexpected success", result.stdout)
        self.assertEqual((output / "report.json").read_text(), "previous report")
        self.assertEqual(sorted(p.name for p in output.iterdir()), ["report.json"])

    def test_renderer_write_errors_are_propagated(self):
        for writer in ("write_text_report", "write_markdown_report", "write_json_report", "write_html_report", "write_actions_report", "write_sarif_report", "render_baseline_snapshot"):
            with self.subTest(writer=writer):
                result = self.bash(f'{writer} /dev/full')
                self.assertNotEqual(result.returncode, 0)

    def test_report_can_be_replaced_atomically(self):
        self.success('FORMATS=json\nwrite_reports\nadd_result TEST-NEW test PASS INFO HIGH new x x x\nwrite_reports')
        report = json.loads((self.root / "reports/report.json").read_text())
        self.assertEqual(report["results"][0]["id"], "TEST-NEW")
        self.assertEqual(sorted(p.name for p in (self.root / "reports").iterdir()), ["report.json"])

    def test_replaced_staging_directory_cannot_redirect_writes_or_cleanup(self):
        victim = self.root / "victim"
        victim.mkdir()
        (victim / "content").write_text("keep")
        result = self.bash('''
stat() {
    command stat "$@" || return
    if [[ "$1" == -c && "${*: -1}" == ./.vpscry-write.* ]]; then
        mv -- "${*: -1}" "$TEST_ROOT/original-stage"
        ln -s -- "$TEST_ROOT/victim" "${*: -1}"
    fi
}
FORMATS=text
write_reports
''')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual((victim / "content").read_text(), "keep")

    def test_report_failure_stops_run_stage(self):
        result = self.bash('''
write_json_report() { return 1; }
FORMATS=json
run_stage Reports output write_reports
printf 'unexpected success'
''')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn("unexpected success", result.stdout)

    def test_baseline_symlink_is_rejected(self):
        victim = self.root / "victim.txt"
        victim.write_text("keep")
        (self.root / "host.baseline").symlink_to(victim)
        result = self.bash('WRITE_BASELINE_FILE="$TEST_ROOT/host.baseline"\nwrite_baseline_snapshot_v09')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(victim.read_text(), "keep")

    def test_baseline_symlink_is_rejected_when_writing_reports(self):
        victim = self.root / "victim.txt"
        victim.write_text("keep")
        (self.root / "host.baseline").symlink_to(victim)
        result = self.bash('WRITE_BASELINE_FILE="$TEST_ROOT/host.baseline"\nFORMATS=text\nwrite_reports')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(victim.read_text(), "keep")

    def test_baseline_cannot_overwrite_report(self):
        result = self.bash('WRITE_BASELINE_FILE="$OUTPUT_DIR/report.json"\nFORMATS=json\nwrite_reports')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse((self.root / "reports").exists())

    def test_evidence_digest_uses_full_sha256(self):
        result = self.success("evidence_hash_v09 axc\nprintf '\\n'\nevidence_hash_v09 ayc")
        expected = ['sha256:' + hashlib.sha256(s.encode()).hexdigest() for s in ("axc", "ayc")]
        self.assertEqual(result.stdout.splitlines(), expected)

    def baseline_change(self, baseline=None, status="PASS"):
        if baseline is not None:
            (self.root / "host.baseline").write_text(baseline)
        code = '''
add_result TEST-EVIDENCE test PASS INFO HIGH Test axc x x
WRITE_BASELINE_FILE="$TEST_ROOT/host.baseline"
'''
        if baseline is None:
            code += 'write_baseline_snapshot_v09\n'
        code += f'R_EVIDENCE[0]=ayc\nR_STATUS[0]={status}\n'
        return self.findings(code + 'BASELINE_FILE="$WRITE_BASELINE_FILE"\ncheck_baseline_diff_v09')["BASELINE-DIFF-001"]

    def test_baseline_detects_same_length_internal_change(self):
        result = self.baseline_change()
        self.assertIn("evidence_changed=1", result["evidence"])
        self.assertTrue((self.root / "host.baseline").read_text().startswith("# VPScry baseline v2\n"))

    def test_baseline_counts_evidence_changes_with_status_change(self):
        result = self.baseline_change(status="FAIL")
        self.assertIn("evidence_changed=1", result["evidence"])
        self.assertIn("worse=1", result["evidence"])

    def test_legacy_baseline_warns_without_fake_evidence_comparison(self):
        result = self.baseline_change("# VPScry baseline v1\nTEST-EVIDENCE\tPASS\tINFO\tlen:3:first:a:last:c\n")
        self.assertEqual(result["status"], "WARN")
        self.assertIn("evidence_changed=0", result["evidence"])
        self.assertIn("evidence_uncomparable=1", result["evidence"])

    def test_invalid_baseline_is_not_accepted(self):
        result = self.baseline_change("# VPScry baseline v2\nTEST-EVIDENCE\tPASS\tINFO\tnot-a-hash\n")
        self.assertEqual(result["status"], "WARN")
        self.assertIn("invalid", result["title"])

    def systemd(self, body):
        return self.findings('systemctl() {\n' + body + '\n}\nfind() { return 0; }\ncheck_systemd')

    def test_systemd_failures_never_become_healthy_empty_lists(self):
        results = self.systemd("return 1")
        for name in ("SVC-SYSTEMD-001", "SVC-FAILED-001", "SVC-TIMER-001", "SVC-INVENTORY-001", "SVC-RESTART-001"):
            self.assertEqual(results[name]["status"], "SKIP", name)

    def test_systemd_successful_empty_lists_pass(self):
        results = self.systemd('[[ "$1" != is-system-running ]] || printf running\nreturn 0')
        for name in ("SVC-SYSTEMD-001", "SVC-FAILED-001", "SVC-TIMER-001", "SVC-RESTART-001"):
            self.assertEqual(results[name]["status"], "PASS", name)

    def test_systemd_failed_units_and_degraded_state_are_reported(self):
        results = self.systemd('''
case "$1" in
    is-system-running) printf degraded; return 1 ;;
    --failed) printf 'example.service loaded failed failed Example\n' ;;
esac
return 0
''')
        for name in ("SVC-SYSTEMD-001", "SVC-FAILED-001", "SVC-TIMER-001"):
            self.assertEqual(results[name]["status"], "FAIL", name)

    def test_systemd_partial_failure_is_not_pass(self):
        results = self.systemd('''
case "$1" in
    is-system-running) printf running ;;
    --failed) printf 'partial output'; return 1 ;;
    list-units) printf 'example.service loaded active running Example\n' ;;
    show) return 1 ;;
esac
return 0
''')
        for name in ("SVC-FAILED-001", "SVC-TIMER-001", "SVC-RESTART-001"):
            self.assertEqual(results[name]["status"], "SKIP", name)

    def test_missing_shadow_database_does_not_pass_account_checks(self):
        results = self.findings('''
getent() { return 1; }
admin_login_backend_v011() { printf unavailable; }
check_identity_policy_v07 "$TEST_ROOT/missing-shadow"
''')
        for name in ("AUTH-AGING-USERS-001", "AUTH-SERVICE-SHELL-001"):
            self.assertEqual(results[name]["status"], "SKIP", name)

    def postgres(self, hba):
        root = self.root / "postgres/17/main"
        root.mkdir(parents=True, exist_ok=True)
        if hba is not None:
            (root / "pg_hba.conf").write_text(hba)
        return self.findings('''
POSTGRES_CONFIG_ROOT="$TEST_ROOT/postgres"
have() { return 1; }
systemctl() { return 1; }
listener_inventory_for_ports() { return 0; }
check_postgresql
''')["DB-PG-HBA-001"]

    def test_postgres_detects_indented_network_trust_and_all_host_types(self):
        for kind in ("host", "hostssl", "hostnossl", "hostgssenc", "hostnogssenc"):
            with self.subTest(kind=kind):
                result = self.postgres(f" \t {kind} all all 0.0.0.0/0 trust\n")
                self.assertEqual(result["status"], "FAIL")

    def test_postgres_scans_beyond_first_eighty_records(self):
        result = self.postgres("local all all peer\n" * 100 + "host all all ::/0 trust\n")
        self.assertEqual(result["status"], "FAIL")
        self.assertIn(":101:", result["evidence"])

    def test_postgres_comments_usernames_and_options_are_not_auth_methods(self):
        result = self.postgres('''
host all trust 127.0.0.1/32 scram-sha-256 # trust
host "database with spaces" "user with spaces" 127.0.0.1 255.255.255.255 scram-sha-256
local all all peer map=trust
''')
        self.assertEqual(result["status"], "PASS")

    def test_postgres_continuation_quotes_and_netmask(self):
        result = self.postgres('host "database name" "user name" 127.0.0.1 255.255.255.255 \\\n trust\n')
        self.assertEqual(result["status"], "FAIL")

    def test_postgres_local_trust_warns(self):
        self.assertEqual(self.postgres('  local all all trust\n')["status"], "WARN")

    def test_postgres_incomplete_files_do_not_pass(self):
        for text in (None, "", "include extra.conf\n", "host invalid\n", 'host "unclosed all all trust\n'):
            with self.subTest(text=text):
                path = self.root / "postgres/17/main/pg_hba.conf"
                if path.exists():
                    path.unlink()
                self.assertEqual(self.postgres(text)["status"], "SKIP")

    def tor(self, config, second=None):
        root = self.root / "tor"
        root.mkdir(exist_ok=True)
        (root / "torrc").write_text(config)
        if second is not None:
            (root / "torrc.second").write_text(second)
        return self.findings('''
TOR_CONFIG_ROOT="$TEST_ROOT/tor"
have() { return 1; }
systemctl() { return 0; }
check_tor_v08
''')

    def test_tor_socket_does_not_authenticate_tcp_control_port(self):
        results = self.tor('ControlPort 9051\nControlSocket /run/tor/control\nCookieAuthentication 0\n')
        self.assertEqual(results["TOR-CONTROL-AUTH-001"]["status"], "FAIL")

    def test_tor_without_onion_services_has_no_permission_failure(self):
        results = self.tor('SocksPort 9050\n')
        self.assertNotIn("TOR-HS-PERM-001", results)

    def test_tor_disabled_control_port_is_not_a_failure(self):
        results = self.tor('ControlPort 0\nControlSocket 0\n')
        self.assertEqual(results["TOR-CONTROL-AUTH-001"]["status"], "INFO")

    def test_tor_cookie_and_password_authentication_pass(self):
        for auth in ('CookieAuthentication 1', 'HashedControlPassword 16:' + 'A' * 58):
            with self.subTest(auth=auth):
                results = self.tor('ControlPort 9051\n' + auth + '\n')
                self.assertEqual(results["TOR-CONTROL-AUTH-001"]["status"], "PASS")

    def test_tor_invalid_password_is_not_counted(self):
        results = self.tor('ControlPort 9051\nHashedControlPassword invalid\n')
        self.assertEqual(results["TOR-CONTROL-AUTH-001"]["status"], "FAIL")

    def test_tor_socket_only_does_not_claim_authentication(self):
        results = self.tor('ControlSocket /run/tor/control\n')
        self.assertEqual(results["TOR-CONTROL-AUTH-001"]["status"], "WARN")

    def test_tor_includes_require_effective_configuration_review(self):
        results = self.tor('%include /etc/tor/auth.conf\nControlPort 9051\n')
        self.assertEqual(results["TOR-CONTROL-AUTH-001"]["status"], "SKIP")

    def test_tor_does_not_merge_authentication_between_instances(self):
        results = self.tor('ControlPort 9051\n', 'CookieAuthentication 1\n')
        self.assertEqual(results["TOR-CONTROL-AUTH-001"]["status"], "SKIP")

    def nft(self, rules, failure=False):
        (self.root / "rules.nft").write_text(rules)
        result = self.success('''
nft() { cat "$TEST_ROOT/rules.nft"; ''' + ('return 1;' if failure else 'return 0;') + ''' }
net_parse_nft
printf '%s|%s|%s\n' "$NET_FW_V4_POLICY" "$NET_FW_V6_POLICY" "$NET_FW_COMPLEX"
printf 'v4:%s\n' "${!NET_FW_ALLOW_V4[@]}"
printf 'v6:%s\n' "${!NET_FW_ALLOW_V6[@]}"
net_policy_result v4 1 "$NET_FW_V4_POLICY"
write_json_report "$TEST_ROOT/result.json"
''')
        report = json.loads((self.root / "result.json").read_text())
        return result.stdout.splitlines(), report["results"][0]

    def test_nft_input_and_output_rules_are_separate(self):
        lines, finding = self.nft('''
table inet filter {
 chain input {
  type filter hook input priority filter; policy drop;
  tcp dport 22 accept
 }
 chain output {
  type filter hook output priority filter; policy accept;
  tcp dport 9999 accept
 }
}
''')
        self.assertEqual(lines[0], "restrictive|restrictive|0")
        self.assertIn("v4:tcp:22", lines)
        self.assertNotIn("v4:tcp:9999", lines)
        self.assertEqual(finding["status"], "PASS")

    def test_nft_unconditional_accept_does_not_prove_restriction(self):
        for rule in ("accept", "counter packets 1 bytes 60 accept", "jump trusted", "tcp dport @ports accept", "ip saddr 10.0.0.0/8 tcp dport 22 accept", "tcp dport 22 drop"):
            with self.subTest(rule=rule):
                lines, finding = self.nft('table ip filter {\n chain input {\n type filter hook input priority 0; policy drop;\n ' + rule + '\n }\n}\n')
                self.assertTrue(lines[0].endswith("|1"))
                self.assertEqual(finding["status"], "WARN")

    def test_nft_families_and_named_input_hook(self):
        lines, finding = self.nft('''
table ip6 filter {
 chain incoming {
  type filter hook input priority 0; policy drop;
  udp dport { 53, 1000-1002 } counter accept
 }
}
table ip filter {
 chain incoming {
  type filter hook input priority 0; policy accept;
 }
}
''')
        self.assertEqual(lines[0], "permissive|restrictive|0")
        self.assertIn("v6:udp:1001", lines)
        self.assertNotIn("v4:udp:53", lines)
        self.assertEqual(finding["status"], "WARN")

    def test_nft_regular_chains_comments_and_stateful_rules(self):
        lines, finding = self.nft('''
table inet filter {
 chain unused {
  tcp dport 1234 accept
 }
 chain input {
  type filter hook input priority 0; policy drop;
  ct state established,related accept
  iifname "lo" accept
  ct state invalid drop
  tcp dport 22 accept comment "} accept tcp dport 1234"
 }
}
''')
        self.assertEqual(lines[0], "restrictive|restrictive|0")
        self.assertNotIn("v4:tcp:1234", lines)
        self.assertEqual(finding["status"], "PASS")

    def test_nft_multiple_input_chains_are_not_flattened(self):
        lines, finding = self.nft('''
table inet filter {
 chain first {
  type filter hook input priority 0; policy drop;
  tcp dport 22 accept
 }
 chain second {
  type filter hook input priority 1; policy drop;
  tcp dport 443 accept
 }
}
''')
        self.assertTrue(lines[0].endswith("|1"))
        self.assertEqual(finding["status"], "WARN")

    def test_nft_failed_query_does_not_parse_partial_stdout(self):
        lines, finding = self.nft('table ip filter {\n chain input {\n type filter hook input priority 0; policy drop;\n }\n}\n', failure=True)
        self.assertEqual(lines[0], "unknown|unknown|1")
        self.assertEqual(finding["status"], "WARN")


if __name__ == "__main__":
    unittest.main()
