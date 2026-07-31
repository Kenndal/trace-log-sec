# Incident fixture manifest

Generated fixtures: `webserver_incidents.log` (2964 lines), `auth_incidents.log` (1203 lines). All timestamps are UTC on 2025-11-12.

Background traffic (the vast majority of both files) is randomized normal activity: browsing, searches, checkouts, employee SSH/sudo sessions, occasional harmless 404s/500s. The scenarios below are the deliberately embedded incidents, in chronological order, for manual verification. Each one states whether today's eight shipped rules (`ssh_brute_force`, `web_login_brute_force`, `web_scanning`, `directory_traversal`, `sql_injection`, `sensitive_file_exposure`, `scanner_user_agent`, `sudo_privilege_escalation`) already catch it, or which remaining shortlisted MVP item (#2 brute-force-then-success, #3 password spraying) it's staged for.

## Off-hours insider credential theft + backdoor account
- **Category:** SSH auth + privilege escalation
- **When:** ~02:15 UTC
- **Actor(s):** carol (from 45.33.12.9, not her usual 10.0.0.13)
- **Status:** PARTIALLY DETECTED - the login itself is still invisible (normal publickey auth, no auth-failure threshold fires), but `sudo_privilege_escalation` now fires on the `/etc/shadow` read, `.aws/credentials` copy, and `useradd`/`usermod` backdoor commands. Full value (flagging the anomalous source IP for carol) still needs a known-source-IP baseline, out of scope for now.
- **What happens:** 02:15 AM login from an unfamiliar external IP, immediately followed by reading /etc/shadow, copying AWS credentials, and creating+privileging a new 'backdoor' user. No failed logins anywhere in this chain, so today's tool sees nothing at all.

## SSH brute force (blocked)
- **Category:** SSH auth
- **When:** ~08:15 UTC
- **Actor(s):** 198.51.100.23
- **Status:** DETECTED today - ssh_brute_force
- **What happens:** 8 failed root logins in 40s, attacker gives up, no success.

## SSH brute force -> success -> credential theft (flagship chain)
- **Category:** SSH auth + privilege escalation
- **When:** ~09:40 UTC
- **Actor(s):** 203.0.113.77 (user 'admin')
- **Status:** PARTIALLY DETECTED - `ssh_brute_force` fires on the failed burst and `sudo_privilege_escalation` now fires separately on the `/etc/shadow` and `id_rsa` reads; they surface as two unrelated findings, not one chain, since sudo lines carry no source IP so the Correlator can't join them. The success event itself is still invisible until item #2 (brute-force-then-success) is built.
- **What happens:** 6 failed SSH passwords in 40s, then a successful login, then sudo cat of /etc/shadow and id_rsa within 35s of login. This is the canonical 'attacker got in and immediately dumped credentials' story.

## Web login brute force (blocked)
- **Category:** Web auth
- **When:** ~10:05 UTC
- **Actor(s):** 198.51.100.45
- **Status:** DETECTED today - web_login_brute_force
- **What happens:** 14 failed POST /login (401) in 55s.

## Web login brute force -> account takeover
- **Category:** Web auth
- **When:** ~11:20 UTC
- **Actor(s):** 192.0.2.88
- **Status:** PARTIALLY DETECTED today - web_login_brute_force fires on the failed burst; the follow-on success + authenticated session use is invisible until item #2 (brute-force-then-success) is built
- **What happens:** 11 failed POST /login (401) in ~55s, then a 200, then the attacker pulls /api/users/me and /dashboard with the new session.

## Web scanning / path enumeration
- **Category:** Web recon
- **When:** ~12:30 UTC
- **Actor(s):** 198.51.100.201
- **Status:** DETECTED today - web_scanning
- **What happens:** 18 distinct 404 paths in ~90s.

## Directory traversal + cross-service recon
- **Category:** Web + SSH
- **When:** ~13:10 UTC
- **Actor(s):** 203.0.113.150
- **Status:** DETECTED today - directory_traversal and ssh_brute_force both fire, and the Correlator merges them into one Incident (same IP, 2 rules, both within the 10-minute window)
- **What happens:** 5 traversal payloads against the web server, then 5 SSH invalid-user probes 3 minutes later from the same IP -- good test of multi-source correlation, not just multi-rule.

## SQL injection probing
- **Category:** Web app
- **When:** ~13:45 UTC
- **Actor(s):** 198.51.100.90
- **Status:** MOSTLY DETECTED today - sql_injection fires with count=5/6. The stacked-query payload ('; DROP TABLE orders--') has no quote character before the comment, so it slips past every current pattern -- worth noting as a real gap in the existing regex set, not a fixture bug.
- **What happens:** 6 SQLi payloads (UNION, tautology, unquoted stacked query, time-based blind) in 42s.

## Password spraying (single username, rotating source IPs)
- **Category:** SSH auth
- **When:** ~14:20-14:27 UTC
- **Actor(s):** 9 IPs -> 'admin', 7 IPs -> 'root'
- **Status:** NOT DETECTED today - ThresholdRule keys strictly on source_ip; each IP here only fires once, well under the per-IP threshold of 5. Needs item #3 (username-keyed aggregation across IPs) from the shortlist.
- **What happens:** One failed attempt per IP against a single target username, spread across 9 (then 7) distinct source IPs so no single IP ever crosses the brute-force threshold.

## Sensitive file / credential exposure probing
- **Category:** Web app
- **When:** ~15:00 UTC
- **Actor(s):** 198.51.100.250
- **Status:** DETECTED - `sensitive_file_exposure` fires (count=13). Two of these requests (/.git/config, /.env.production) return 200 -- an actual exposed-secret finding, not just a probe -- but the rule can't yet see status codes, so all 13 fold into one HIGH finding; check `Finding.evidence` for the 200s.
- **What happens:** 13 requests for source-control, env, backup and key-material paths in 24s; 2 of them succeed (200).

## Known scanner / attack-tool user agents
- **Category:** Web recon
- **When:** ~15:30 UTC
- **Actor(s):** 5 IPs (sqlmap, Nikto, Nessus, masscan UAs + one blank UA)
- **Status:** DETECTED - `scanner_user_agent` fires once per attacking IP (5 findings, MEDIUM).
- **What happens:** Each tool identifies itself in its own User-Agent string -- the cheapest possible detection once a signature rule targets 'user_agent'.
