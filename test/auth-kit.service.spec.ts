import { Test, TestingModule } from '@nestjs/testing';
import { AuthKitService } from '../src/auth-kit.service';
import { JwtService } from '@nestjs/jwt';
import { AUTH_KIT_OPTIONS } from '../src/constants';
import { UnauthorizedException } from '@nestjs/common';

jest.mock('otplib', () => ({
  generateSecret: jest.fn().mockReturnValue('mock-secret'),
  generateURI: jest.fn().mockImplementation(({ label, issuer }) => `otpauth://totp/${issuer}:${label}?secret=mock-secret`),
  verify: jest.fn().mockResolvedValue({ valid: true }),
}));

describe('AuthKitService', () => {
  let service: AuthKitService;
  let jwtService: JwtService;
  let redisMock: any;

  const mockOptions = {
    jwt: {
      accessSecret: 'a]3Fj$kL9!mNpQ2rStUvWxYz0123456',
      refreshSecret: 'b]4Gk$lM0!nOrP3sTuVwXyZa1234567',
      accessTtl: '15m',
      refreshTtl: '7d',
    },
    twoFactor: {
      appName: 'TestApp',
    },
  };

  beforeEach(async () => {
    redisMock = {
      set: jest.fn().mockResolvedValue('OK'),
      get: jest.fn(),
      del: jest.fn().mockResolvedValue(1),
      keys: jest.fn().mockResolvedValue([]),
      sadd: jest.fn().mockResolvedValue(1),
      smembers: jest.fn().mockResolvedValue([]),
      expire: jest.fn().mockResolvedValue(1),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthKitService,
        {
          provide: JwtService,
          useValue: {
            sign: jest.fn().mockReturnValue('mock-token'),
            verify: jest.fn(),
          },
        },
        {
          provide: AUTH_KIT_OPTIONS,
          useValue: mockOptions,
        },
        {
          provide: 'REDIS_CLIENT',
          useValue: redisMock,
        },
      ],
    }).compile();

    service = module.get<AuthKitService>(AuthKitService);
    jwtService = module.get<JwtService>(JwtService);
  });

  describe('createTokenPair', () => {
    it('should return access and refresh tokens and store RT in redis', async () => {
      const result = await service.createTokenPair('user-1', 'admin');

      expect(result).toEqual({
        accessToken: 'mock-token',
        refreshToken: 'mock-token',
      });
      expect(jwtService.sign).toHaveBeenCalledTimes(2);
      expect(redisMock.set).toHaveBeenCalledWith(
        expect.stringMatching(/^rt:user-1:/),
        'valid',
        'EX',
        604800,
      );
      expect(redisMock.sadd).toHaveBeenCalledWith(
        'rt:family:user-1',
        expect.any(String),
      );
      expect(redisMock.expire).toHaveBeenCalledWith(
        'rt:family:user-1',
        604800,
      );
    });
  });

  describe('refreshTokens', () => {
    it('should rotate tokens if valid', async () => {
      jwtService.verify = jest.fn().mockReturnValue({ sub: 'user-1', role: 'admin', jti: 'jti-1' });
      redisMock.get.mockResolvedValue('valid');
      jest.spyOn(service, 'createTokenPair').mockResolvedValue({ accessToken: 'new-at', refreshToken: 'new-rt' });

      const result = await service.refreshTokens('old-rt');

      expect(result).toEqual({ accessToken: 'new-at', refreshToken: 'new-rt' });
      expect(redisMock.set).toHaveBeenCalledWith('rt:user-1:jti-1', 'used', 'EX', 604800);
    });

    it('should detect reuse and revoke family', async () => {
      jwtService.verify = jest.fn().mockReturnValue({ sub: 'user-1', role: 'admin', jti: 'jti-1' });
      redisMock.get.mockResolvedValue('used');
      redisMock.smembers.mockResolvedValue(['jti-1', 'jti-2']);

      await expect(service.refreshTokens('stolen-rt')).rejects.toThrow(UnauthorizedException);
      expect(redisMock.del).toHaveBeenCalledWith('rt:user-1:jti-1', 'rt:user-1:jti-2', 'rt:family:user-1');
    });

    it('should throw if token not found in redis', async () => {
      jwtService.verify = jest.fn().mockReturnValue({ sub: 'user-1', role: 'admin', jti: 'jti-1' });
      redisMock.get.mockResolvedValue(null);

      await expect(service.refreshTokens('invalid-rt')).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('revokeSession', () => {
    it('should blocklist user and delete refresh tokens', async () => {
      redisMock.smembers.mockResolvedValue(['jti-1']);

      await service.revokeSession('user-1');

      expect(redisMock.set).toHaveBeenCalledWith('blocklist:user:user-1', 'revoked', 'EX', 604800);
      expect(redisMock.del).toHaveBeenCalledWith('rt:user-1:jti-1', 'rt:family:user-1');
    });
  });

  describe('revokeToken', () => {
    it('should blocklist specific access token hash', async () => {
      await service.revokeToken('some-access-token');

      expect(redisMock.set).toHaveBeenCalledWith(
        expect.stringMatching(/^blocklist:token:/),
        'BLOCKED',
        'EX',
        900,
      );
    });
  });

  describe('2FA', () => {
    it('should setup 2FA', () => {
      const result = service.setup2FA('test@example.com');
      expect(result).toHaveProperty('secret');
      expect(result).toHaveProperty('otpauthUrl');
    });

    it('should verify 2FA code', async () => {
      const isValid = await service.verify2FA('secret', '123456');
      expect(typeof isValid).toBe('boolean');
    });
  });
});
