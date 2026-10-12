# Red-Team-Notes
# Case Study: Full Endpoint Compromise — Home Lab AD Attack Chain

**Type:** Self-authorized home lab exercise
**Target:** Windows 11 workstation (physical device, isolated lab network)
**Objective:** Demonstrate an end-to-end attacker path from initial foothold to full SYSTEM compromise and credential recovery, in order to build and validate detection coverage for each stage

---

## Overview

This exercise simulated a full attack lifecycle against a hardened Windows 11 endpoint, starting from a position of valid low-privilege local credentials. The goal wasn't just "pop the box" — it was to walk every stage of the kill chain deliberately enough to understand *why* each technique works, what conditions make it possible, and what a defender would need in place to catch it. That last part fed directly into the Sysmon/Wazuh detection engineering side of the lab.

**Framework used:** Havoc (open-source C2) for payload delivery and post-exploitation tasking.

---

## Skills Demonstrated

| Stage | Technique Category | ATT&CK ID |
|---|---|---|
| Execution | Windows Management Instrumentation | T1047 |
| Defense Evasion | Masquerading (legitimate-process naming) | T1036.005 |
| Privilege Escalation | Access Token Manipulation | T1134 |
| Persistence | Scheduled Task | T1053.005 |
| Credential Access | OS Credential Dumping — SAM/SYSTEM hives | T1003.002 |
| Credential Access | Offline password cracking | T1110.002 |

---

## What Was Demonstrated

**Initial access and execution.** Starting from valid local admin credentials, I used Windows Management Instrumentation — a built-in Windows management interface — to execute code remotely. It's a technique commonly favored in real engagements specifically because it's native to the OS and doesn't require dropping unfamiliar binaries to disk, which keeps the initial footprint low.

**Defense evasion.** The delivered payload was disguised under a filename resembling a legitimate background update process. Masquerading like this is one of the most common ways attackers blend into normal process activity on an endpoint, and it's a good reminder of why file *name* and *path* alone are weak signals — legitimate-looking isn't the same as legitimate.

**Privilege escalation.** Rather than relying on a missing patch, escalation came from identifying a background service running as SYSTEM whose access token could be impersonated. Token manipulation is a good example of a privilege-escalation class that doesn't depend on a CVE at all — it depends on how services and permissions are configured, which is exactly why it still works on a fully patched Windows 11 box.

**Persistence.** To survive a reboot, I set up a scheduled task configured to execute at startup under the elevated context already obtained. Scheduled tasks are one of the highest-value persistence mechanisms to actually hunt for, since legitimate admin tooling creates them constantly — the challenge (and the detection opportunity) is in separating signal from noise.

**Credential access and validation.** With SYSTEM-level access, I extracted the SAM and SYSTEM registry hives — the pair needed to decrypt locally stored password hashes — and ran GPU-accelerated offline cracking against the recovered NTLM hashes to validate password strength.

---

## Key Takeaways

- Full compromise didn't require a single CVE. Every stage relied on native Windows functionality and legitimate administrative mechanisms used the wrong way — which is the normal reality of how real intrusions unfold, and why detection has to focus on *behavior* rather than waiting on patch status.
- Each stage above maps to something detectable: WMI process-creation lineage, unsigned/renamed processes in non-standard paths, token-impersonation event patterns, new non-Microsoft scheduled tasks, and registry-hive access to SAM/SYSTEM outside of normal backup activity. Building Sysmon/Wazuh rules against each of these was the direct follow-on to this exercise.
- This is also why defense-in-depth matters more than any single control: no individual step here was exotic, but the *chain* of them unmonitored is what adds up to full compromise.

---

## Remediation Recommendations

1. **Constrain WMI usage** — restrict remote WMI execution to designated admin workstations via firewall/GPO; alert on WMI process creation from non-standard sources.
2. **Harden service account permissions** — audit services running as SYSTEM for tokens that are impersonable by lower-privileged accounts.
3. **Monitor scheduled task creation** — alert on new tasks created outside of approved deployment/patch tooling, especially those targeting non-Microsoft paths.
4. **Protect credential material** — enable Credential Guard where supported, and alert on any non-backup process accessing the SAM/SYSTEM registry hives.
5. **Enforce strong local password policy** — mitigate the impact of any future hash extraction by raising the cost of offline cracking.

---

*This write-up reflects a self-authorized exercise against personally-owned hardware in an isolated lab environment, conducted to build and validate detection engineering skills.*

