import { Injectable, Inject, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AUTH_KIT_OPTIONS, AUTH_KIT_REDIS_CLIENT } from './constants';
import { AuthKitOptions } from './interfaces/auth-kit-options.interface';
import { randomUUID } from 'crypto';
import { Redis } from 'ioredis';
import { generateSecret, generateURI, verify } from 'otplib';
import { createHash } from 'crypto';

@Injectable()
export class AuthKitService {
  constructor(
    @Inject(AUTH_KIT_OPTIONS) private options: AuthKitOptions,
    @Inject(AUTH_KIT_REDIS_CLIENT) private redis: Redis,
    private jwtService: JwtService,
  ) {}

  async createTokenPair(userId: string, role: string) {
    const payload = { sub: userId, role };
    const jti = randomUUID();

    const accessToken = this.jwtService.sign(
      { ...payload, jti },
      {
        secret: this.options.jwt.accessSecret,
        expiresIn: this.options.jwt.accessTtl as any,
        algorithm: this.options.jwt.algorithm,
      },
    );

    const refreshToken = this.jwtService.sign(
      { ...payload, jti },
      {
        secret: this.options.jwt.refreshSecret,
        expiresIn: this.options.jwt.refreshTtl as any,
        algorithm: this.options.jwt.algorithm,
      },
    );

    const ttl = this.parseToSeconds(this.options.jwt.refreshTtl);

    await this.redis.set(`rt:${userId}:${jti}`, 'valid', 'EX', ttl);

    await this.redis.sadd(`rt:family:${userId}`, jti);
    await this.redis.expire(`rt:family:${userId}`, ttl);

    return { accessToken, refreshToken };
  }

  async refreshTokens(refreshToken: string) {
    try {
      const decoded = this.jwtService.verify(refreshToken, {
        secret: this.options.jwt.refreshSecret,
        algorithms: this.options.jwt.algorithm ? [this.options.jwt.algorithm] : undefined,
      });

      const { sub, role, jti } = decoded;
      const redisKey = `rt:${sub}:${jti}`;
      const familyKey = `rt:family:${sub}`;

      const ttl = this.parseToSeconds(this.options.jwt.refreshTtl);
      // Atomic Get-and-Set to prevent race conditions
      const tokenState = await this.redis.set(redisKey, 'used', 'EX', ttl, 'GET');

      if (tokenState === 'used') {
        // Token reuse detected! Revoke the entire family (session)
        const jtis = await this.redis.smembers(familyKey);
        if (jtis.length > 0) {
          for (const id of jtis) {
            await this.redis.set(`blocklist:jti:${id}`, 'revoked', 'EX', ttl);
          }
        }
        await this.revokeSession(sub);
        throw new UnauthorizedException('Token reuse detected. Session revoked.');
      }

      if (!tokenState) throw new UnauthorizedException('Invalid refresh token.');


      return this.createTokenPair(sub, role);
    } catch (e) {
      if (e instanceof UnauthorizedException) throw e;
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }

  async revokeSession(userId: string) {
    await this.redis.set(
      `blocklist:user:${userId}`,
      'revoked',
      'EX',
      this.parseToSeconds(this.options.jwt.refreshTtl),
    );

    const familyKey = `rt:family:${userId}`;
    const jtis = await this.redis.smembers(familyKey);
    if (jtis.length > 0) {
      const keysToDelete = jtis.map(id => `rt:${userId}:${id}`);
      await this.redis.del(...keysToDelete, familyKey);
    }
  }

  async revokeToken(accessToken: string) {
    const hash = this.hashToken(accessToken);
    await this.redis.set(
      `blocklist:token:${hash}`,
      'BLOCKED',
      'EX',
      this.parseToSeconds(this.options.jwt.accessTtl),
    );
  }

  setup2FA(userEmail: string) {
    const secret = generateSecret();
    const otpauthUrl = generateURI({
      label: userEmail,
      issuer: this.options.twoFactor?.appName || 'App',
      secret,
    });
    return { secret, otpauthUrl };
  }

  async verify2FA(secret: string, code: string): Promise<boolean> {
    const result = await verify({ token: code, secret });
    return result.valid;
  }

  async logout(userId: string, accessToken?: string) {
    if (accessToken) {
      await this.revokeToken(accessToken);
    }
    await this.revokeSession(userId);
  }

  private hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  private parseToSeconds(ttl: string | number): number {
    if (typeof ttl === 'number') return Math.floor(ttl);

    // Support 'ms' style strings without the dependency
    const match = ttl.match(/^(\d+)\s*(ms|s|m|h|d|w|y|seconds?|minutes?|hours?|days?|weeks?|years?)$/i);
    if (!match) {
      throw new Error(`Invalid TTL format: ${ttl}. Expected format: '15m', '10 hours', etc.`);
    }

    const value = parseInt(match[1], 10);
    const unit = match[2].toLowerCase();

    const multipliers: Record<string, number> = {
      ms: 0.001,
      s: 1,
      sec: 1,
      second: 1,
      seconds: 1,
      m: 60,
      min: 60,
      minute: 60,
      minutes: 60,
      h: 3600,
      hour: 3600,
      hours: 3600,
      d: 86400,
      day: 86400,
      days: 86400,
      w: 604800,
      week: 604800,
      weeks: 604800,
      y: 31536000,
      year: 31536000,
      years: 31536000,
    };

    const multiplier = multipliers[unit] || multipliers[unit.replace(/s$/, '')] || 0;
    return Math.floor(value * multiplier);
  }
}
