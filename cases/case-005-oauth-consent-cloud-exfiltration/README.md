# Case 005 - OAuth Consent Cloud Exfiltration

## Scenario

An unverified OAuth app named `Northstar Document Sync` was granted broad permissions by `maya.hassan`, a finance director. Shortly after consent, the app used Graph API access to download sensitive SharePoint and OneDrive files, created an external sharing link, uploaded data to an external cloud storage domain, and added a service principal credential.

## Learner Objective

Determine whether this was normal SaaS activity or malicious OAuth abuse. Identify the affected user, suspicious app, dangerous scopes, accessed files, likely exfiltration path, MITRE mapping, severity, and containment actions.

## Expected Verdict

Confirmed Incident

## Expected Severity

Critical
