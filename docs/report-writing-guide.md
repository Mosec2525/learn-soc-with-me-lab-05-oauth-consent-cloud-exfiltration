# Report Writing Guide

An OAuth consent investigation report should explain why MFA and password status do not close the case.

## Good Report Structure

1. Summary
2. Scope
3. Timeline
4. OAuth consent evidence
5. Token and Graph API activity
6. Sensitive file access and DLP evidence
7. Persistence evidence
8. MITRE mapping
9. Severity rationale
10. Containment and hunting actions

## Weak Report Pattern

```text
User clicked a bad link. Reset password.
```

This misses the cloud app risk. OAuth consent grants may remain active even when the user's password is reset.

## Strong Report Pattern

```text
maya.hassan received a board-pack themed phishing email and clicked a link that led to OAuth consent for an unverified app named Northstar Document Sync. The app was granted Files.Read.All, Mail.Read, and offline_access, then used delegated Graph API access from 203.0.113.219 to enumerate finance resources, download sensitive SharePoint and OneDrive files, create an anonymous external sharing link, and upload data to fileshare-sync.example. A client secret was later added to the service principal, indicating persistence. This supports a confirmed critical OAuth token abuse and cloud data exposure incident.
```
