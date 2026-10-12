# Red-Team-Notes

## About Me

I'm Jessie Parker, a cybersecurity practitioner working across offensive security and detection engineering. My background is nearly eight years of enterprise Tier 2 technical support in healthcare IT (HCA Healthcare/Parallon), which gave me a deep, practical understanding of how real production environments actually behave — and where the gaps are that attackers go after.

I run a home lab focused on Active Directory attack chains and the detection engineering needed to catch them, working hands-on with tools like BloodHound, Impacket, NetExec, Rubeus, and Certipy on the offensive side, and Sysmon/Wazuh on the defensive side. This repo collects write-ups from that lab work — case studies that walk through what I did, why it worked, and what a defender would need in place to catch it.

I'm currently pursuing offensive security and detection engineering roles. You can find my other projects on [GitHub](https://github.com/jp101216), connect with me on [LinkedIn](https://linkedin.com/in/jessie-parker-17a495421), or check out my [PowerShell IR/ops toolkit](https://github.com/jp101216/PowerShell-Ops-IR-Toolkit).

---

## Write-Ups

| Write-Up | Focus |
|---|---|
| [Full Endpoint Compromise — Home Lab AD Attack Chain](./goad-lab-case-study.md) | End-to-end Windows 11 compromise: WMI execution, token-impersonation privilege escalation, scheduled-task persistence, and credential extraction — mapped to MITRE ATT&CK with detection and remediation guidance for each stage |

*More write-ups added as lab work continues — upcoming topics include Sysmon/Wazuh detection rule development and APT threat intelligence breakdowns.*

---

## License

MIT — see [`LICENSE`](./LICENSE).
