# NestJS AuthKit

NestJS AuthKit is a production-grade token management and session control library for NestJS. It handles JWT access/refresh token pairs, refresh token rotation with reuse detection, Redis-backed session revocation, RBAC, and TOTP-based 2FA.

This library manages the **token layer** of authentication. Your application is responsible for verifying user credentials (password hashing, OAuth, etc.) before calling AuthKit to issue tokens.

## Key Features

- **Advanced Token Lifecycle**: Access and Refresh tokens with "Refresh Token Family" rotation.
- **Automatic Reuse Detection**: Detects refresh token reuse (indicating potential theft) and invalidates the entire session family.
- **Instant Revocation**: Revoke specific tokens or terminate all sessions for a user via Redis.
- **Native 2FA Support**: Generate TOTP secrets/URIs and verify codes for Google Authenticator/Authy.
- **Performance Optimized**: Uses Redis Sets and SHA256-hashed blocklists for fast lookups.
- **Flexible Access Control**: Decorators for Role-Based Access Control (RBAC) and public route exclusion.
- **Graceful Shutdown**: Redis connections are properly closed on application shutdown.
- **Async Configuration**: Fully compatible with NestJS `ConfigService` via `forRootAsync`.

## Installation

```bash
npm i @mohamedsaba/nestjs-authkit
```

*Requires an active Redis instance for session management.*

## Quick Start

### 1. Register the Module

Import `AuthKitModule` into your root `AppModule`. Use `forRootAsync` to securely load secrets from environment variables.

```typescript
import { AuthKitModule } from '@mohamedsaba/nestjs-authkit';
import { ConfigModule, ConfigService } from '@nestjs/config';

@Module({
  imports: [
    AuthKitModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        jwt: {
          accessSecret: config.get('JWT_ACCESS_SECRET'),  // min 32 characters
          refreshSecret: config.get('JWT_REFRESH_SECRET'), // min 32 characters
          accessTtl: '15m',
          refreshTtl: '7d',
          algorithm: 'HS256',
        },
        redis: {
          host: config.get('REDIS_HOST'),
          port: config.get('REDIS_PORT'),
        },
        twoFactor: {
          enabled: true,
          appName: 'MySecureApp',
        },
      }),
    }),
  ],
})
export class AppModule {}
```

### 2. Issue Tokens After Authentication

AuthKit does not verify credentials — your application handles that. After verifying a user's identity, call `createTokenPair` to issue tokens.

```typescript
import { AuthKitService } from '@mohamedsaba/nestjs-authkit';

@Injectable()
export class AuthService {
  constructor(private authKit: AuthKitService) {}

  async login(email: string, password: string) {
    const user = await this.usersService.findByEmail(email);
    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) throw new UnauthorizedException();

    return this.authKit.createTokenPair(user.id, user.role);
    // Returns: { accessToken, refreshToken }
  }

  async refresh(refreshToken: string) {
    return this.authKit.refreshTokens(refreshToken);
  }

  async logout(userId: string, accessToken?: string) {
    return this.authKit.logout(userId, accessToken);
  }
}
```

### 3. Protect Your Routes

Apply `AuthKitGuard` globally or on specific controllers. Use `@Public()` to exclude routes.

```typescript
import { AuthKitGuard, Public, Roles, RoleGuard, CurrentUser } from '@mohamedsaba/nestjs-authkit';
import { UseGuards, Controller, Get } from '@nestjs/common';

@Controller('users')
@UseGuards(AuthKitGuard, RoleGuard)
export class UsersController {

  @Public()
  @Get('login')
  async login() {
    // Public route — no auth required
  }

  @Roles('admin')
  @Get('dashboard')
  async getDashboard(@CurrentUser() user) {
    // Protected by Auth + RBAC
  }
}
```

## API Reference

### `AuthKitService`

| Method | Description |
| :--- | :--- |
| `createTokenPair(userId, role)` | Issues an access + refresh token pair. Stores refresh token state in Redis. |
| `refreshTokens(refreshToken)` | Rotates tokens. Detects reuse and revokes the session family if compromised. |
| `revokeToken(accessToken)` | Blocklists a specific access token (SHA256-hashed) until its natural expiration. |
| `revokeSession(userId)` | Terminates all active sessions for a user. |
| `logout(userId, accessToken?)` | Convenience method — optionally revokes a token, then revokes the session. |
| `setup2FA(userEmail)` | Returns `{ secret, otpauthUrl }` for TOTP setup. |
| `verify2FA(secret, code)` | Verifies a TOTP code. Returns `Promise<boolean>`. |

### Decorators

| Decorator | Description |
| :--- | :--- |
| `@Public()` | Exempts a route from authentication. |
| `@Roles('admin', 'editor')` | Restricts access to users with matching roles. |
| `@CurrentUser()` | Extracts the authenticated user payload from the request. |

## Configuration Options

| Option | Type | Description |
| :--- | :--- | :--- |
| `jwt.accessSecret` | `string` | **Required**. Min 32 characters. Secret for signing access tokens. |
| `jwt.refreshSecret` | `string` | **Required**. Min 32 characters. Secret for signing refresh tokens. |
| `jwt.accessTtl` | `string` | TTL for access tokens (e.g., `'15m'`, `'1h'`). |
| `jwt.refreshTtl` | `string` | TTL for refresh tokens (e.g., `'7d'`, `'30d'`). |
| `jwt.algorithm` | `string` | JWT algorithm (`HS256`, `HS384`, `HS512`, `RS256`). |
| `redis.host` | `string` | Redis host. |
| `redis.port` | `number` | Redis port. |
| `redis.password` | `string` | Redis password (optional). |
| `twoFactor.enabled` | `boolean` | Enable 2FA support. |
| `twoFactor.appName` | `string` | Label shown in authenticator apps. |

## Core Concepts

### Token Rotation & Reuse Detection

AuthKit uses a "Family" approach to refresh tokens. Every time a refresh token is used, a new one is issued, and the old one is marked as "used." If a "used" token is presented again, AuthKit assumes a breach has occurred and immediately revokes all tokens in that user's session family.

### Session Revocation

JWTs are stateless by nature. AuthKit adds a thin stateful layer using Redis:
- **Token-level**: Access tokens are SHA256-hashed and stored in a blocklist.
- **User-level**: A user blocklist entry invalidates all tokens for that user.
- Both blocklist entries auto-expire aligned with the token TTL.

## Development and Testing

```bash
npm test       # Run tests
npm run build  # Build the project
```

## License

MIT — see [LICENSE](LICENSE) for details.
