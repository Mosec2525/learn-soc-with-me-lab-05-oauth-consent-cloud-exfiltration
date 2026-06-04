# MITRE ATT&CK Mapping

This lab maps to MITRE ATT&CK Enterprise techniques for cloud and SaaS intrusion activity.

## T1566.002 - Phishing: Spearphishing Link

The initial access path is a phishing email that sends the user to an OAuth consent flow.

Lab evidence:

- `mail-5001` shows the board-pack themed email.
- `click-5101` shows `maya.hassan` clicked the OAuth consent link.
- The redirect chain requests broad permissions for `Northstar Document Sync`.

## T1528 - Steal Application Access Token

The attacker does not need the user's password after consent. The malicious app receives delegated access and uses the resulting token to call cloud APIs.

Lab evidence:

- `oauth-5401` shows consent granted to `Northstar Document Sync`.
- `signin-5202` shows non-interactive Graph access by the app from `203.0.113.219`.
- `graph-5501` through `graph-5504` show API access after consent.

## T1078.004 - Valid Accounts: Cloud Accounts

The activity uses valid cloud identity context through the affected user's delegated access.

Lab evidence:

- `signin-5201` shows a successful interactive sign-in for `maya.hassan`.
- Later API activity is associated with the user's delegated permissions.

## T1087.004 - Account Discovery: Cloud Account

The app uses Graph API calls to discover accessible users, drives, and SharePoint sites.

Lab evidence:

- `graph-5501` enumerates the user's OneDrive root.
- `graph-5502` searches for finance SharePoint sites.

## T1530 - Data from Cloud Storage

The suspicious app accesses sensitive files in OneDrive and SharePoint.

Lab evidence:

- `graph-5503` downloads `Board_MandA_Strategy_Q2.pdf`.
- `graph-5504` downloads `Executive-Compensation-2026.xlsx`.
- `sp-5601` through `sp-5603` show sensitive file downloads.

## T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage

The lab shows probable exfiltration through a cloud storage-style destination.

Lab evidence:

- `sp-5604` creates an anonymous external sharing link.
- `proxy-5801` uploads data to `fileshare-sync.example`.

## T1098.001 - Account Manipulation: Additional Cloud Credentials

The suspicious app adds a service principal credential after file access, which may preserve access.

Lab evidence:

- `audit-5302` shows a `client_secret` added to `Northstar Document Sync`.

## Analyst Note

The strongest mapping is the behavior chain, not any single log line. The lab should be mapped after correlating email, click, consent, token use, file access, DLP, external sharing, and app credential changes.
