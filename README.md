# Red-Team-Notes

## About Me

I'm Jessie Parker, a cybersecurity practitioner working across offensive security and detection engineering. My background is nearly eight years of enterprise Tier 2 technical support in healthcare IT (HCA Healthcare/Parallon), which gave me a deep, practical understanding of how real production environments actually behave — and where the gaps are that attackers go after.

I run a home lab focused on Active Directory attack chains and the detection engineering needed to catch them, working hands-on with tools like BloodHound, Impacket, NetExec, Rubeus, and Certipy on the offensive side, and Sysmon/Wazuh on the defensive side. This repo collects write-ups from that lab work — case studies that walk through what I did, why it worked, and what a defender would need in place to catch it.

I'm currently pursuing offensive security and detection engineering roles. You can find my other projects on [GitHub](https://github.com/jp101216), connect with me on [LinkedIn](https://linkedin.com/in/jessie-parker-17a495421), or check out my [PowerShell IR/ops toolkit](https://github.com/jp101216/PowerShell-Ops-IR-Toolkit).

---

## Write-Ups

| Write-Up | Focus |
|---|---|
| [Full Endpoint Compromise — Home Lab AD Attack Chain](./Case%20Study%3A%20Full%20Endpoint%20Compromise%20-%20Home%20Lab%20AD%20Attack%20Chain.md) | End-to-end Windows 11 compromise: WMI execution, token-impersonation privilege escalation, scheduled-task persistence, and credential extraction — mapped to MITRE ATT&CK with detection and remediation guidance for each stage |
| [Adversary Emulation — Nessus Recon → SMB Relay → Pass-the-Hash](./Adversary%20Emulation%20Case%20Study.md) | Two-host chain from an unauthenticated LAN position: Nessus/Nmap recon, LLMNR/NBT-NS poisoning and SMB relay, SAM dump, and a Pass-the-Hash pivot enabled by local admin password reuse — with a wmiexec / smbexec / atexec comparison after Defender disrupted WMI, per-host DFIR artifacts, and remediation |
| [Adversary Emulation — Custom C2, UAC Bypass & BYOVD](./Adversary%20Emulation%20Case%20Study%20-%20Custom%20C2%20to%20SYSTEM%20via%20BYOVD.md) | Assumed-breach emulation with a custom Rust implant over DNS-over-HTTPS: in-memory evasion, UAC bypass, BYOVD kernel escalation to SYSTEM, and scheduled-task persistence — scored against a Defender, Sysmon, and Wazuh stack, with Sigma rules and remediation for each gap |

*More write-ups added as lab work continues — upcoming topics include Sysmon/Wazuh detection rule development and APT threat intelligence breakdowns.*

---

## License

MIT — see [`LICENSE`](./LICENSE).
