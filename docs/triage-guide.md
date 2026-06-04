# SOC Triage Guide

This guide gives learners a repeatable workflow for Lab 05.

## 1. Start With The Alert

Capture:

- Alert ID
- Affected user
- Suspicious app name and app ID
- Requested OAuth scopes
- Source IPs
- Sensitive files involved
- Initial severity
- Detection source

## 2. Validate The Phishing Path

Look for:

- External sender or lookalike domain
- SPF, DKIM, or DMARC failures
- User click event
- Redirect to an OAuth consent flow
- App created shortly before the email

The important point is that the lure leads to consent, not just credential theft.

## 3. Inspect OAuth Consent

High-interest signals:

- Unverified publisher
- New or unknown app
- Broad scopes such as `Files.Read.All`, `Mail.Read`, or `offline_access`
- Redirect URI outside the approved app catalog
- Consent from a high-value user

## 4. Separate Sign-In From Token Abuse

The interactive sign-in can look normal. The suspicious part is what happens after consent.

Ask:

- Was MFA satisfied only for the user sign-in?
- Did app token activity start from a different IP?
- Did non-interactive sign-ins or Graph calls appear after consent?
- Did the app access resources the user normally does not access?

## 5. Review Cloud File Activity

Check:

- SharePoint and OneDrive downloads
- External sharing links
- Sensitive labels
- DLP matches
- Uploads to external storage domains

## 6. Check For Persistence

OAuth incidents often survive a password reset.

Check:

- App credentials
- Service principal changes
- Refresh token use
- New app role assignments
- Additional consent grants

## 7. Decide Verdict

Use these verdicts:

| Verdict | Meaning |
|---|---|
| False Positive | No meaningful suspicious activity after review |
| Benign True Positive | Rule fired correctly, but activity is expected or authorized |
| Suspicious Activity | Suspicious evidence exists, but compromise or exposure is not confirmed |
| Confirmed Incident | Unauthorized token-based activity, sensitive access, external sharing, or persistence occurred |

For this lab, the expected verdict is `Confirmed Incident`.

## 8. Recommend Actions

Recommended first actions:

- Revoke OAuth consent grants
- Disable or remove the suspicious service principal
- Remove app credentials
- Revoke user sessions and refresh tokens
- Remove external sharing links
- Block the destination domain
- Audit all recent high-risk OAuth consents
- Hunt for app ID, redirect URI, source IP, scopes, and destination domain
