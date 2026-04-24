import { Test, TestingModule } from '@nestjs/testing';
import { AuthKitGuard } from '../src/guards/auth-kit.guard';
import { JwtService } from '@nestjs/jwt';
import { Reflector } from '@nestjs/core';
import { AUTH_KIT_OPTIONS } from '../src/constants';
import { UnauthorizedException } from '@nestjs/common';

describe('AuthKitGuard', () => {
  let guard: AuthKitGuard;
  let jwtService: JwtService;
  let reflector: Reflector;
  let redisMock: any;

  const mockOptions = {
    jwt: {
      accessSecret: 'secret',
      refreshSecret: 'refresh',
      accessTtl: '15m',
      refreshTtl: '7d',
    },
  };

  beforeEach(async () => {
    redisMock = {
      get: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthKitGuard,
        {
          provide: JwtService,
          useValue: {
            verify: jest.fn(),
          },
        },
        {
          provide: Reflector,
          useValue: {
            getAllAndOverride: jest.fn(),
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

    guard = module.get<AuthKitGuard>(AuthKitGuard);
    jwtService = module.get<JwtService>(JwtService);
    reflector = module.get<Reflector>(Reflector);
  });

  it('should allow public routes', async () => {
    reflector.getAllAndOverride = jest.fn().mockReturnValue(true);
    const context = {
      getHandler: jest.fn(),
      getClass: jest.fn(),
      switchToHttp: jest.fn(),
    } as any;

    expect(await guard.canActivate(context)).toBe(true);
  });

  it('should throw Unauthorized if no token', async () => {
    reflector.getAllAndOverride = jest.fn().mockReturnValue(false);
    const context = {
      getHandler: jest.fn(),
      getClass: jest.fn(),
      switchToHttp: jest.fn().mockReturnValue({
        getRequest: () => ({
          headers: {},
        }),
      }),
    } as any;

    await expect(guard.canActivate(context)).rejects.toThrow(UnauthorizedException);
  });

  it('should throw if token is blocklisted', async () => {
    reflector.getAllAndOverride = jest.fn().mockReturnValue(false);
    redisMock.get.mockResolvedValue('BLOCKED');
    const context = {
      getHandler: jest.fn(),
      getClass: jest.fn(),
      switchToHttp: jest.fn().mockReturnValue({
        getRequest: () => ({
          headers: {
            authorization: 'Bearer valid-token',
          },
        }),
      }),
    } as any;

    await expect(guard.canActivate(context)).rejects.toThrow('Token revoked');
  });

  it('should verify token and check user blocklist', async () => {
    reflector.getAllAndOverride = jest.fn().mockReturnValue(false);
    redisMock.get.mockResolvedValue(null); // Not blocked
    jwtService.verify = jest.fn().mockReturnValue({ sub: 'user-1' });
    
    const request = {
      headers: {
        authorization: 'Bearer valid-token',
      },
    };
    const context = {
      getHandler: jest.fn(),
      getClass: jest.fn(),
      switchToHttp: jest.fn().mockReturnValue({
        getRequest: () => request,
      }),
    } as any;

    expect(await guard.canActivate(context)).toBe(true);
    expect(request['user']).toEqual({ sub: 'user-1' });
  });
});
