# Completed Sample Report

## Summary

`maya.hassan` received a board-pack themed phishing email and clicked a link that led to OAuth consent for an unverified app named `Northstar Document Sync`. The app received broad delegated permissions, used Microsoft Graph-style activity from `203.0.113.219` to access sensitive SharePoint and OneDrive files, created an anonymous external sharing link, uploaded data to `fileshare-sync.example`, and added a service principal credential. This is a confirmed critical OAuth token abuse and cloud data exposure incident.

## Scope

- Affected user: `maya.hassan`
- Suspicious app: `Northstar Document Sync`
- App ID: `app-5e21-9c70-docsync`
- Source IP: `203.0.113.219`
- Destination domain: `fileshare-sync.example`
- Files involved:
  - `Board_MandA_Strategy_Q2.pdf`
  - `Executive-Compensation-2026.xlsx`
  - `Payroll-Forecast-June.xlsx`

## Timeline

| Time UTC | Event | Evidence |
|---|---|---|
| 13:21 | Phishing email delivered | `mail-5001` |
| 13:23 | User clicked consent link | `click-5101` |
| 13:24 | User completed sign-in with MFA | `signin-5201` |
| 13:24 | OAuth consent granted | `oauth-5401` |
| 13:27 | Non-interactive Graph sign-in from new IP | `signin-5202` |
| 13:29 | App searched finance SharePoint sites | `graph-5502` |
| 13:31 | Board document downloaded | `graph-5503`, `sp-5601` |
| 13:34 | Anonymous external sharing link created | `sp-5604` |
| 13:36 | DLP matched sensitive content | `dlp-5701`, `dlp-5702` |
| 13:38 | Upload to external storage domain | `proxy-5801` |
| 13:41 | Service principal credential added | `audit-5302` |

## MITRE ATT&CK Mapping

| Technique | Evidence |
|---|---|
| `T1566.002` | Board-pack themed OAuth consent phishing link |
| `T1528` | Delegated app token used for Graph API access |
| `T1078.004` | Cloud account context used through delegated user access |
| `T1087.004` | Graph API discovery of drives and finance sites |
| `T1530` | Sensitive data accessed from SharePoint and OneDrive |
| `T1567.002` | Upload to external cloud storage-style destination |
| `T1098.001` | Service principal credential added for persistence |

## Verdict

Confirmed Incident

## Severity

Critical

## Recommended Actions

- Revoke consent for `Northstar Document Sync`.
- Disable or delete the suspicious service principal.
- Remove the added client secret.
- Revoke sessions and refresh tokens for `maya.hassan`.
- Remove anonymous external sharing links.
- Block `fileshare-sync.example` and related indicators.
- Audit recent OAuth consent grants with `Files.Read.All`, `Mail.Read`, or `offline_access`.
- Hunt for `app-5e21-9c70-docsync`, `northstar-docsync.example`, `203.0.113.219`, and `fileshare-sync.example`.
- Escalate to incident response, legal, and privacy stakeholders because sensitive business data was exposed.

## Remaining Questions

- Did any other users grant consent to the same app?
- Were the shared links accessed by external parties?
- Did the app read mailbox content using `Mail.Read`?
- Are there additional service principal credentials or app role assignments?
