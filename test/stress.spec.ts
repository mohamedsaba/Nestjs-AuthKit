import { Test, TestingModule } from '@nestjs/testing';
import { AuthKitService } from '../src/auth-kit.service';
import { AUTH_KIT_OPTIONS, AUTH_KIT_REDIS_CLIENT } from '../src/constants';
import { JwtService } from '@nestjs/jwt';
import { UnauthorizedException } from '@nestjs/common';

jest.mock('otplib', () => ({
  generateSecret: jest.fn(),
  generateURI: jest.fn(),
  verify: jest.fn(),
}));

describe('Nestjs-AuthKit Harsh Stress Test', () => {
  let service: AuthKitService;
  let redisData: Map<string, any> = new Map();
  let redisSets: Map<string, Set<string>> = new Map();

  // Robust Redis Mock to handle actual state during concurrency
  const redisMock = {
    set: jest.fn().mockImplementation(async (key, value, ...args) => {
      // Simulate real redis delay
      await new Promise(resolve => setTimeout(resolve, Math.random() * 5));
      
      const oldVal = redisData.get(key) || null;
      
      // Handle SET ... GET
      const hasGet = args.includes('GET');
      
      redisData.set(key, value);
      
      return hasGet ? oldVal : 'OK';
    }),

    get: jest.fn().mockImplementation(async (key) => {
      await new Promise(resolve => setTimeout(resolve, Math.random() * 5));
      return redisData.get(key) || null;
    }),
    del: jest.fn().mockImplementation(async (...keys) => {
      for (const key of keys) {
        if (Array.isArray(key)) {
            key.forEach(k => redisData.delete(k));
        } else {
            redisData.delete(key);
        }
      }
      return 1;
    }),
    sadd: jest.fn().mockImplementation(async (key, member) => {
      if (!redisSets.has(key)) redisSets.set(key, new Set());
      redisSets.get(key)!.add(member);
      return 1;
    }),
    smembers: jest.fn().mockImplementation(async (key) => {
      return Array.from(redisSets.get(key) || []);
    }),
    expire: jest.fn().mockResolvedValue(1),
  };

  beforeEach(async () => {
    redisData.clear();
    redisSets.clear();
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthKitService,
        {
          provide: AUTH_KIT_OPTIONS,
          useValue: {
            jwt: {
              accessSecret: 'stress-test-secret-long-enough-32-chars',
              refreshSecret: 'stress-test-secret-long-enough-32-chars',
              accessTtl: '15m',
              refreshTtl: '7d',
            },
          },
        },
        {
          provide: AUTH_KIT_REDIS_CLIENT,
          useValue: redisMock,
        },
        {
          provide: JwtService,
          useValue: {
            sign: jest.fn().mockImplementation((payload) => `token.${JSON.stringify(payload)}`),
            verify: jest.fn().mockImplementation((token) => {
                const parts = token.split('.');
                return JSON.parse(parts[1]);
            }),
          },
        },
      ],
    }).compile();

    service = module.get<AuthKitService>(AuthKitService);
  });

  it('Scenario 1: Mass Concurrent Logins (500 users)', async () => {
    const start = Date.now();
    const concurrency = 500;
    
    const requests = Array.from({ length: concurrency }).map((_, i) => 
      service.createTokenPair(`user-${i}`, 'user')
    );

    const results = await Promise.all(requests);
    const duration = Date.now() - start;

    expect(results).toHaveLength(concurrency);
    expect(redisData.size).toBeGreaterThanOrEqual(concurrency); // At least one RT per user
    console.log(`[STRESS] Mass Login: 500 users in ${duration}ms`);
  });

  it('Scenario 2: Refresh Token Race Condition (100 simultaneous hits)', async () => {
    // 1. Create a valid token
    const { refreshToken } = await service.createTokenPair('victim-user', 'user');
    
    // 2. Hammer refreshTokens with the SAME token 100 times simultaneously
    const concurrency = 100;
    const requests = Array.from({ length: concurrency }).map(() => 
      service.refreshTokens(refreshToken)
    );

    const outcomes = await Promise.allSettled(requests);
    
    const successes = outcomes.filter(o => o.status === 'fulfilled');
    const failures = outcomes.filter(o => o.status === 'rejected');

    console.log(`[STRESS] RT Race: ${successes.length} success, ${failures.length} revoked`);

    expect(successes.length).toBe(1);
    expect(failures.length).toBe(99);

    
    // Ensure the family was revoked
    const isUserBlocked = await redisMock.get('blocklist:user:victim-user');
    expect(isUserBlocked).toBe('revoked');
  });

  it('Scenario 3: Mass Session Revocation', async () => {
    const userCount = 100;
    // Pre-populate
    await Promise.all(Array.from({ length: userCount }).map((_, i) => 
        service.createTokenPair(`user-${i}`, 'user')
    ));

    const start = Date.now();
    const revocations = Array.from({ length: userCount }).map((_, i) => 
        service.revokeSession(`user-${i}`)
    );

    await Promise.all(revocations);
    const duration = Date.now() - start;

    for (let i = 0; i < userCount; i++) {
        expect(await redisMock.get(`blocklist:user:user-${i}`)).toBe('revoked');
    }
    console.log(`[STRESS] Mass Revocation: 100 sessions in ${duration}ms`);
  });
});
