1. Privileged escalation / sensitive credential access (sudo â root â /etc/shadow, /etc/passwd, SSH keys, .aws/credentials)
Highest severity, zero current coverage. Your johndoe line is a completed credential-dump, and nothing today even looks at sudo command lines. Fits your existing signature rule shape almost directly â just needs a new match target on the sudo COMMAND= field.

2. Brute-force â success (account takeover)
A failed-login burst is "someone tried"; a failed burst immediately followed by a success on the same identity is "someone's in" â an order-of-magnitude severity jump your ThresholdRule currently can't express (it just clears state once the burst subsides). Both sample IPs (10.0.0.50 on SSH and web) demonstrate exactly this pattern, so it's directly testable.

     Brute-force → success (account takeover) — possible, but the most invasive of the five. This isn't "count crossings of one predicate," it's "N failures, then a success on the same identity" — a different shape (two predicates, and the finding fires on the resolving event rather than the threshold-crossing event). You could still build it as an extension of ThresholdRule rather than a new algorithm class: keep the existing failure-window machinery, add an optional second predicate (e.g. escalate_match="success_after_failures") that, on match, inspects the current window count for that identity and — if it's already over threshold — emits a critical finding referencing both the burst and the success. It reuses the deque/eviction engine wholesale, but it does stretch ThresholdRule's contract (single predicate, fire-on-crossing) more than #3 does, so I'd treat it as the last of the five to tackle, and review the resulting class carefully for readability rather than assuming it's still a one-liner.


3. Password spraying (distributed low-and-slow brute force)
Real coverage gap: your threshold rule keys everything on source_ip, so an attacker spreading attempts across many IPs (or hammering many usernames from one IP faster than your window) walks straight through. This is one of the most common real-world credential attacks and your MVP currently only defends the vertical case.

    Password spraying — yes, and it's a clean generalization. ThresholdRule already has the right shape (sliding window + distinct_by counting) but hardcodes the aggregation key to entry.source_ip. Spraying is the same algorithm on the other axis: key by username instead of IP, and count distinct source IPs hitting that username within the window. That means adding one new parameter, key_by (mirroring the existing distinct_by preset pattern), and swapping entry.source_ip for a KEY_EXTRACTORS[key_by](entry) lookup in inspect/_events/_active. Everything else — eviction, counting, finding lifecycle — is reused untouched. Worth doing; it's a small, principled extension of a class that's already halfway there.


4. Sensitive file/credential exposure over HTTP
Cheapest win on the list â pure data extension to the existing signature rule, no new code path. Widen the pattern set beyond traversal/SQLi to .git/, id_rsa, .env-adjacent secrets, backup dumps (.bak, .sql). Directly relevant since .env/config.php already show up in your sample as recon targets.

5. Known attack-tool / scanner fingerprinting via User-Agent
Also cheap â user_agent is already a supported TARGET_EXTRACTORS key, so this is a config-only addition (sqlmap, nikto, nmap, nessus, masscan, blank UA). Lower severity than the others but very high signal-to-effort ratio, and it turns passive recon into an earlier tripwire before the exploit attempts even land.