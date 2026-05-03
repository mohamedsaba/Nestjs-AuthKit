import { Test, TestingModule } from '@nestjs/testing';

jest.mock('otplib', () => ({
  generateSecret: jest.fn(),
  generateURI: jest.fn(),
  verify: jest.fn(),
}));

import { AuthKitService } from '../src/auth-kit.service';

import { RoleGuard } from '../src/guards/role.guard';
import { AUTH_KIT_OPTIONS, AUTH_KIT_REDIS_CLIENT } from '../src/constants';
import { Reflector } from '@nestjs/core';
import { ForbiddenException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

describe('Nestjs-AuthKit Fortification', () => {
  let service: AuthKitService;
  let guard: RoleGuard;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthKitService,
        RoleGuard,
        {
          provide: AUTH_KIT_OPTIONS,
          useValue: {
            jwt: {
              accessSecret: 'secret',
              refreshSecret: 'secret',
              accessTtl: '15m',
              refreshTtl: '7d',
            },
          },
        },
        {
          provide: AUTH_KIT_REDIS_CLIENT,
          useValue: {
            set: jest.fn(),
            get: jest.fn(),
            sadd: jest.fn(),
            expire: jest.fn(),
            smembers: jest.fn(),
            del: jest.fn(),
          },
        },
        {
          provide: JwtService,
          useValue: {
            sign: jest.fn(),
            verify: jest.fn(),
          },
        },
        {
          provide: Reflector,
          useValue: {
            get: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<AuthKitService>(AuthKitService);
    guard = module.get<RoleGuard>(RoleGuard);
  });

  describe('TTL Parsing (parseToSeconds)', () => {
    it('should parse various string formats', () => {
      expect((service as any).parseToSeconds('15m')).toBe(900);
      expect((service as any).parseToSeconds('1h')).toBe(3600);
      expect((service as any).parseToSeconds('10 hours')).toBe(36000);
      expect((service as any).parseToSeconds('1 day')).toBe(86400);
      expect((service as any).parseToSeconds('3w')).toBe(1814400);
      expect((service as any).parseToSeconds('1week')).toBe(604800);
    });

    it('should parse numeric values', () => {
      expect((service as any).parseToSeconds(300)).toBe(300);
    });

    it('should throw on invalid format', () => {
      expect(() => (service as any).parseToSeconds('invalid')).toThrow('Invalid TTL format');
    });
  });

  describe('Multi-role RBAC (RoleGuard)', () => {
    it('should allow user with matching string role', () => {
      const reflector = (guard as any).reflector;
      reflector.get.mockReturnValue(['admin']);
      
      const context = {
        getHandler: () => ({}),
        switchToHttp: () => ({
          getRequest: () => ({ user: { role: 'admin' } }),
        }),
      } as any;

      expect(guard.canActivate(context)).toBe(true);
    });

    it('should allow user with matching role in array', () => {
      const reflector = (guard as any).reflector;
      reflector.get.mockReturnValue(['admin']);
      
      const context = {
        getHandler: () => ({}),
        switchToHttp: () => ({
          getRequest: () => ({ user: { role: ['editor', 'admin'] } }),
        }),
      } as any;

      expect(guard.canActivate(context)).toBe(true);
    });

    it('should deny user if no roles match', () => {
      const reflector = (guard as any).reflector;
      reflector.get.mockReturnValue(['admin']);
      
      const context = {
        getHandler: () => ({}),
        switchToHttp: () => ({
          getRequest: () => ({ user: { role: ['editor', 'viewer'] } }),
        }),
      } as any;

      expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
    });
  });

  describe('AT JTI Revocation (Vulnerability Fix)', () => {
    it('should include jti in Access Token payload', async () => {
      const signSpy = jest.spyOn((service as any).jwtService, 'sign').mockReturnValue('mock-at');
      
      await service.createTokenPair('user-1', 'admin');
      
      // First call is for AT, second is for RT
      const atPayload = signSpy.mock.calls[0][0] as any;
      expect(atPayload).toHaveProperty('jti');
      expect(typeof atPayload.jti).toBe('string');
    });

    it('should revoke all family JTIs on reuse detection', async () => {
      const redis = (service as any).redis;
      redis.set.mockResolvedValue('used'); // SET ... GET returns 'used' (reuse)
      redis.smembers.mockResolvedValue(['jti-1', 'jti-2']);
      
      const signSpy = jest.spyOn((service as any).jwtService, 'verify').mockReturnValue({ sub: 'user-1', role: 'admin', jti: 'jti-2' });

      try {
        await service.refreshTokens('some-rt');
      } catch (e) {
        // Expected
      }

      // Should have blocked both JTIs in the family
      expect(redis.set).toHaveBeenCalledWith('blocklist:jti:jti-1', 'revoked', 'EX', expect.any(Number));
      expect(redis.set).toHaveBeenCalledWith('blocklist:jti:jti-2', 'revoked', 'EX', expect.any(Number));
    });

  });
});
