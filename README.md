# NestJS AuthKit

NestJS AuthKit is a production-grade authentication and session management library designed to handle the complexities of modern security workflows. It provides a robust, drop-in solution for JWT-based authentication, two-factor authentication (2FA), and stateful session control using Redis.

Unlike simple JWT implementations, AuthKit focuses on the "Day 2" problems of authentication: token reuse detection, instant session revocation, and performance-conscious security checks.

## Key Features

- **Advanced Token Lifecycle**: Implements Access and Refresh tokens with "Refresh Token Family" rotation.
- **Automatic Reuse Detection**: Detects if a refresh token has been reused (indicating a potential theft) and automatically invalidates the entire session family.
- **Instant Revocation**: Support for revoking specific tokens or terminating all active sessions for a user via a high-performance Redis backend.
- **Native 2FA Support**: Built-in methods for generating secrets, URI strings for Google Authenticator/Authy, and verifying TOTP codes.
- **Performance Optimized**: Uses Redis Sets and optimized lookups to ensure authentication checks remain fast even under high load.
- **Flexible Access Control**: Simple decorators for Role-Based Access Control (RBAC) and public route exclusion.
- **Async Configuration**: Fully compatible with NestJS `ConfigService` via `forRootAsync`.

## Installation

```bash
npm install nestjs-authkit
```

*Note: This library requires an active Redis instance for session management.*

## Quick Start

### 1. Register the Module

Import `AuthKitModule` into your root `AppModule`. We recommend using `forRootAsync` to securely load secrets.

```typescript
import { AuthKitModule } from 'nestjs-authkit';
import { ConfigModule, ConfigService } from '@nestjs/config';

@Module({
  imports: [
    AuthKitModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        jwt: {
          accessSecret: config.get('JWT_ACCESS_SECRET'),
          refreshSecret: config.get('JWT_REFRESH_SECRET'),
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

### 2. Protect Your Routes

Apply the `AuthKitGuard` globally or on specific controllers. Use the `@Public()` decorator to exclude routes like Login or Register.

```typescript
import { AuthKitGuard, Public, Roles, RoleGuard } from 'nestjs-authkit';
import { UseGuards, Controller, Get } from '@nestjs/common';

@Controller('users')
@UseGuards(AuthKitGuard, RoleGuard)
export class UsersController {
  
  @Public()
  @Get('login')
  async login() {
    // Public route
  }

  @Roles('admin')
  @Get('dashboard')
  async getDashboard() {
    // Protected by Auth and RBAC
  }
}
```

## Core Concepts

### Token Rotation & Security
AuthKit uses a "Family" approach to refresh tokens. Every time a refresh token is used, a new one is issued, and the old one is marked as "used." If a "used" token is presented again, AuthKit assumes a breach has occurred and immediately revokes all tokens belonging to that user's session family.

### Session Revocation
While JWTs are stateless by nature, AuthKit adds a thin stateful layer using Redis. 
- `revokeToken(token)`: Blocklists a specific access token until its natural expiration.
- `revokeSession(userId)`: Instantly terminates all active sessions for a specific user.
- `logout(userId, accessToken?)`: A convenience method that handles both.

### Two-Factor Authentication
Setting up 2FA is straightforward:

```typescript
// 1. Setup
const { secret, otpauthUrl } = this.authKitService.setup2FA('user@example.com');

// 2. Verify
const isValid = await this.authKitService.verify2FA(userStoredSecret, userInputCode);
```

## Configuration Options

| Option | Type | Description |
| :--- | :--- | :--- |
| `jwt.accessSecret` | `string` | **Required**. Secret for signing access tokens. |
| `jwt.refreshSecret` | `string` | **Required**. Secret for signing refresh tokens. |
| `jwt.accessTtl` | `string` | TTL for access tokens (e.g., '15m', '1h'). |
| `jwt.refreshTtl` | `string` | TTL for refresh tokens (e.g., '7d', '30d'). |
| `jwt.algorithm` | `string` | JWT algorithm (HS256, RS256, etc.). |
| `redis.host` | `string` | Redis host. |
| `redis.port` | `number` | Redis port. |
| `twoFactor.appName` | `string` | The label shown in Authenticator apps. |

## Development and Testing

The project is fully tested with Jest. To run the suite:

```bash
npm test
```

To build the project:

```bash
npm run build
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
