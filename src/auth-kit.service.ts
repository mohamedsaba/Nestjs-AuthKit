import { Injectable, Inject, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AUTH_KIT_OPTIONS } from './constants';
import { AuthKitOptions } from './interfaces/auth-kit-options.interface';
import { v4 as uuidv4 } from 'uuid';
import { Redis } from 'ioredis';
import { generateSecret, generateURI, verify } from 'otplib';
import { createHash } from 'crypto';
import { UserRegistrationDto } from './dtos/user-registration.dto';

@Injectable()
export class AuthKitService {
  constructor(
    @Inject(AUTH_KIT_OPTIONS) private options: AuthKitOptions,
    @Inject('REDIS_CLIENT') private redis: Redis,
    private jwtService: JwtService,
  ) {}

  async register(payload: UserRegistrationDto) {
    return this.login(payload.email, payload.role);
  }

  async login(userId: string, role: string) {
    const payload = { sub: userId, role };
    const jti = uuidv4();

    const accessToken = this.jwtService.sign(payload, {
      secret: this.options.jwt.accessSecret,
      expiresIn: this.options.jwt.accessTtl as any,
      algorithm: this.options.jwt.algorithm,
    });

    const refreshToken = this.jwtService.sign(
      { ...payload, jti },
      {
        secret: this.options.jwt.refreshSecret,
        expiresIn: this.options.jwt.refreshTtl as any,
        algorithm: this.options.jwt.algorithm,
      },
    );

    const ttl = this.parseToSeconds(this.options.jwt.refreshTtl);
    
    // Store valid refresh token state
    await this.redis.set(`rt:${userId}:${jti}`, 'valid', 'EX', ttl);
    
    // Add JTI to the user's token family set (avoiding KEYS in the future)
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
      
      const tokenState = await this.redis.get(redisKey);

      if (tokenState === 'used') {
        // Token reuse detected! Invalidate the whole family.
        const jtis = await this.redis.smembers(familyKey);
        if (jtis.length > 0) {
          const keysToDelete = jtis.map(id => `rt:${sub}:${id}`);
          await this.redis.del(...keysToDelete, familyKey);
        }
        throw new UnauthorizedException('Token reuse detected. Session revoked.');
      }

      if (!tokenState) throw new UnauthorizedException('Invalid refresh token.');

      // Mark current token as used
      await this.redis.set(
        redisKey,
        'used',
        'EX',
        this.parseToSeconds(this.options.jwt.refreshTtl),
      );

      return this.login(sub, role);
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
      this.parseToSeconds(this.options.jwt.accessTtl),
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

  private parseToSeconds(ttl: string): number {
    const match = ttl.match(/^(\d+)([smhd])$/);
    if (!match) {
      throw new Error(`Invalid TTL format: ${ttl}. Expected format: '15m', '1h', etc.`);
    }
    const value = parseInt(match[1], 10);
    const unit = match[2];
    
    const multipliers = {
      s: 1,
      m: 60,
      h: 3600,
      d: 86400,
    };
    
    return value * (multipliers[unit] || 0);
  }
}