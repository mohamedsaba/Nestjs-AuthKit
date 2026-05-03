# Changelog

All notable changes to this project will be documented in this file.

## [1.2.0] - 2026-05-03

### 🚨 Security Fixes
- **Atomic Token Rotation**: Implemented atomic `SET ... GET` operations for refresh token rotation to prevent race conditions during concurrent refresh attempts.
- **Access Token Revocation**: Added `jti` (JWT ID) to Access Tokens and implemented family-wide revocation. When refresh token reuse is detected, all associated Access Tokens are now immediately invalidated via the Redis blocklist.
- **Unique Injection Tokens**: Switched to `Symbol` for the Redis client provider (`AUTH_KIT_REDIS_CLIENT`) to prevent Dependency Injection collisions in consuming applications.

### ✨ Features
- **Robust TTL Parsing**: Integrated a new TTL parsing engine supporting human-readable strings like `'10 hours'`, `'3 weeks'`, `'15m'`, etc.
- **Enterprise RBAC**: Updated `RoleGuard` to support `user.role` as either a string or an array of strings, enabling complex permission structures.
- **Redis Resilience**: Added an exponential backoff `retryStrategy` and connection event listeners (`connect`, `error`) to improve observability and stability during Redis downtime.

### 🐛 Bug Fixes
- Fixed potential 500 errors when passing non-standard TTL formats.
- Fixed `RoleGuard` failing for users with multiple roles.

### 🧪 Testing
- Added a new `fortification` test suite for security validation.
- Added a `stress` test suite to verify concurrency and race condition resilience.
