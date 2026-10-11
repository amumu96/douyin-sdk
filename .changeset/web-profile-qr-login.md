---
"douyin-im": patch
---

Add explicit pure Node web QR authentication with fresh per-login keys, Passport signing and CSRF, terminal failures, Session-bound ticket validation and read-only same-account self verification. Return candidate state only; never import browser authentication, mutate native IM login, persist credentials or write a profile automatically. Real confirmed-login acceptance remains pending.
