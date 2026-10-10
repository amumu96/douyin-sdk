---
"douyin-im": patch
---

Check the account-owned web Session before avatar upload and again before profile commit. Distinguish unauthenticated/business/challenge responses from a different UID, persist validated same-Session Cookie refreshes, and refuse to overwrite credentials provisioned while a request is in flight. Keep read-only verification and single-attempt profile submission; authentication failures never trigger automatic login or profile retries.
