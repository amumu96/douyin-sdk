---
"douyin-im": patch
---

Fix profile writes after account login by using a verified account-owned web session in pure Node, with web ticket signatures, the observed CSRF fallback header and Node Dtrait. Stop stale avatar operations between upload stages and before the profile POST with optional per-operation cancellation and dispatch callbacks. Require the server's requested-value echo for success; uncertain writes are never replayed.
