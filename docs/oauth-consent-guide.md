# OAuth Consent Guide

OAuth consent lets an application request access to resources on behalf of a user or organization.

## Why Consent Abuse Matters

An attacker may not need to steal the user's password if the user grants a malicious application access to data. The app can use tokens to access resources through APIs.

## High-Risk Signals

- Unknown or unverified publisher
- New app registration
- Broad file, mail, directory, or offline access scopes
- Consent granted by a high-value user
- Redirect URI on a lookalike or newly observed domain
- Non-interactive sign-ins after consent
- API activity from cloud hosting infrastructure

## Scopes In This Lab

| Scope | Why It Matters |
|---|---|
| `Files.Read.All` | Allows broad file read access through delegated permissions |
| `Mail.Read` | Allows mailbox access |
| `offline_access` | Allows refresh token-style access after the initial session |
| `User.Read` | Common low-risk scope by itself, but suspicious when bundled with broad scopes |

## Analyst Note

Containment must remove the app access. Password reset alone is incomplete.
