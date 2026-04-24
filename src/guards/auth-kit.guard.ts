import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, Inject } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { AUTH_KIT_OPTIONS } from '../constants';
import { AuthKitOptions } from '../interfaces/auth-kit-options.interface';
import { Redis } from 'ioredis';
import { createHash } from 'crypto';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';

@Injectable()
export class AuthKitGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private reflector: Reflector,
    @Inject(AUTH_KIT_OPTIONS) private options: AuthKitOptions,
    @Inject('REDIS_CLIENT') private redis: Redis,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) return true;

    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);
    if (!token) throw new UnauthorizedException();

    try {
      // 1. Check Token-level Blocklist
      const tokenHash = this.hashToken(token);
      const isTokenBlocked = await this.redis.get(`blocklist:token:${tokenHash}`);
      if (isTokenBlocked) throw new UnauthorizedException('Token revoked');

      const payload = this.jwtService.verify(token, {
        secret: this.options.jwt.accessSecret,
        algorithms: this.options.jwt.algorithm ? [this.options.jwt.algorithm] : undefined,
      });

      // 2. Check User-level Blocklist
      const isUserBlocked = await this.redis.get(`blocklist:user:${payload.sub}`);
      if (isUserBlocked) throw new UnauthorizedException('Session revoked');

      request.user = payload;
      return true;
    } catch (e) {
      if (e instanceof UnauthorizedException) throw e;
      throw new UnauthorizedException();
    }
  }

  private extractTokenFromHeader(request: any): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }

  private hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }
}