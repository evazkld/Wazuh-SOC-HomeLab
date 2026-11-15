# Incident Report: Simulated Brute Force Followed by Local Admin Account Creation

| | |
|---|---|
| **Date** | 14 November 2026 |
| **Environment** | Wazuh 4.14.8 (SIEM/XDR), Windows 11 Home VM on VirtualBox |
| **Affected host** | `win11-vm` (agent ID 002, 10.0.2.4) |
| **Analyst** | `Evdokia Zigka Kaldeli` |
| **Incident type** | Simulated activity (home lab) |
| **Severity if real** | High |

## 1. Summary

Wazuh detected repeated failed logons on `win11-vm`, followed by the creation of a new local user that was added to the Administrators group about 52 seconds later. In a real environment, this sequence (possible credential guessing, then a new privileged account) would indicate credential access followed by persistence and should be escalated. In this lab, both actions were simulated by me to test detection.

## 2. Timeline

All times are as shown in the Wazuh dashboard.

| Time | Activity | Wazuh alert |
|------|----------|-------------|
| 17:01:38 | Several failed logons at the Windows lock screen | Rule 100002, level 10 (built on rule 60122, event 4625) |
| 17:05:03 | Local user `testuser` created | Rule 60109, level 8 (event 4720) |
| 17:05:03 | `testuser` added to the Users group (automatic) | Rule 60170, level 5 (event 4732) |
| 17:05:55 | `testuser` added to the Administrators group | Rule 60154, level 12 (event 4732) |

## 3. Detection Details

- **Custom rule 100002:** fires when base rule 60122 (failed logon) matches 2 times within 60 seconds against the same account SID. Description: "Custom Alert: A possible Brute Force attack was detected." Level 10.
- **Brute force alert:** raised on 14 Nov 2026 at 17:01:38 for event 4625, targeted account `vboxuser`, MITRE ID T1110.
- **Account creation:** built-in rule 60109, "User account enabled or created", level 8.
- **Group changes:** built-in rules 60170 ("Users Group Changed", level 5) and 60154 ("Administrators Group Changed", level 12). Both are based on Windows event 4732.
- Only one alert of level 12 or above appeared in the 24-hour window: the Administrators group change.

## 4. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|----|
| Credential Access | Brute Force | T1110 |
| Persistence | Account Manipulation | T1098 |
| Defense Evasion / Privilege Escalation | Domain Policy Modification | T1484 |

## 5. Tier 1 Triage

Questions I would answer for a real alert like this, with the lab findings:

| Question | Finding |
|----------|---------|
| Is the targeted account real? | Yes, `vboxuser`, the local account on `win11-vm` (`targetUserName` in the alert) |
| Where did the failed logons come from? | Local console (lock screen), not a remote source |
| Did a successful logon follow the failures? | Yes, I logged in normally afterwards |
| Who created `testuser`, and was it authorised? | Created by me from an elevated PowerShell session as part of the test |
| Was the new account added to a privileged group? | Yes, Administrators, 52 seconds after creation |
| Is the host or the account critical? | Not in this lab. In production I would check asset criticality and ownership first |

## 6. Verdict and Escalation

**Verdict:** true positive.

In a real environment I would **escalate to Tier 2** because:

- a new account was created and granted administrator rights within a minute
- the account change followed a burst of failed logons
- the creating user and the change were not covered by an approved change request

## 7. Tuning

Rule 100002 uses a threshold of 2 failures in 60 seconds. I chose this because the Windows account lockout stopped failed attempts from accumulating, so a higher threshold never fired reliably in the lab. In production I would raise it to roughly 5-10 failures and add context such as source IP, to avoid alerting on ordinary typing mistakes.

## 8. Recommendations

- Enforce an account lockout and strong password policy, and enable MFA where possible
- Alert on every addition to privileged groups, and require a matching change ticket
- Add a correlation rule: new account created (4720), then added to Administrators (4732) within a few minutes
- Tune rule 100002 for production volumes before relying on it
- Review administrator group membership regularly

## 9. Evidence

Screenshots are in the [`screenshots/`](screenshots/) folder:

- `01-agent-active.png`: agent connected and active
- `02-powershell-simulation.png`: the simulated commands
- `03-threat-hunting-overview.png` and `04-mitre-attack-dashboard.png`: overview and ATT&CK mapping
- `06-custom-rule-xml.png` and `07-custom-rule-details.png`: custom rule 100002
- `08-account-creation-alert.png`: event 4720 (rule 60109)
- `09-group-change-alerts.png`: event 4732 (rules 60170 and 60154)
