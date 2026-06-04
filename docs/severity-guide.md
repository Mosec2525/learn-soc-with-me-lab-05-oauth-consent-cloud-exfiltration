# Severity Guide

Use this model for the Learn SOC With Me series.

## Severity Levels

| Severity | Use When |
|---|---|
| Informational | Activity is noteworthy but not suspicious by itself |
| Low | Suspicious activity with limited scope and no sensitive resource access |
| Medium | Suspicious OAuth or cloud behavior without confirmed sensitive access |
| High | Confirmed token abuse, affected account, or sensitive access without clear exfiltration |
| Critical | Sensitive data exposure, external sharing, probable exfiltration, privileged app abuse, or persistence |

## Lab 05 Severity

Expected severity: `Critical`

Reason:

- A high-value finance user granted consent to an unverified app
- The app received broad file and mail scopes
- App token activity came from a new cloud hosting source
- Sensitive board, compensation, and payroll files were downloaded
- External sharing links were created
- DLP matched sensitive content
- Data was uploaded to an external cloud storage domain
- A service principal credential was added after access

This is `Critical` because the lab shows sensitive business data exposure plus persistence, not just suspicious consent.
