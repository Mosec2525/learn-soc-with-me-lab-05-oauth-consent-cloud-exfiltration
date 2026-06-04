# Cloud File Activity Guide

Cloud file investigations should connect identity, app, API, file, DLP, and network evidence.

## Useful Evidence

| Evidence | Why It Matters |
|---|---|
| OAuth consent grant | Shows the app was allowed to access data |
| Non-interactive sign-in | Shows token-based app access |
| Graph API activity | Shows what the app requested |
| SharePoint and OneDrive audit logs | Shows file access and sharing |
| DLP alerts | Shows sensitive content was involved |
| Proxy logs | Shows possible external upload volume |

## Lab 05 Pattern

```text
Email lure
  -> URL click
    -> OAuth consent grant
      -> Graph API enumeration
        -> sensitive file download
          -> external sharing link
            -> upload to external cloud storage
              -> service principal credential added
```

## Analyst Questions

- Which app accessed the file?
- Was the app approved?
- Which scopes were granted?
- Which files were downloaded or shared?
- Did DLP classify the content as sensitive?
- Did network logs show upload after download?
- What access remains after password reset?
