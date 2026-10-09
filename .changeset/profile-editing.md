---
"douyin-im": minor
---

Add profile editing: `account.setSignature()`, `account.setNickname()`, `account.setAvatar()` and `account.uploadAvatar()`, plus the standalone `ProfileEditor`. Each change submits one field, succeeds only when Douyin echoes the requested value, reports the daily limit with `retryAt`, and never replays a change. Avatars upload through ImageX before `avatar_uri` is committed.
