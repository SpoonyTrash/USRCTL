# Changelog

## Unreleased

- The legacy `PasswordStatusInfo` constructor parameters `last_changed`,
  `password_expires`, `password_inactive`, and `account_expires` remain available
  for one minor release and will be removed in the next major version. Use their
  corresponding `_at` parameters instead.
