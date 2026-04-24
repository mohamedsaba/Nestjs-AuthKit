import { Module, DynamicModule, Global, Provider } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AuthKitService } from './auth-kit.service';
import { AuthKitOptions, AuthKitModuleAsyncOptions, AuthKitOptionsFactory } from './interfaces/auth-kit-options.interface';
import { AUTH_KIT_OPTIONS } from './constants';
import Redis from 'ioredis';
import { AuthKitGuard } from './guards/auth-kit.guard';
import { RoleGuard } from './guards/role.guard';

@Global()
@Module({})
export class AuthKitModule {
  static forRoot(options: AuthKitOptions): DynamicModule {
    this.validateOptions(options);
    return {
      module: AuthKitModule,
      imports: [JwtModule.register({})],
      providers: [
        {
          provide: AUTH_KIT_OPTIONS,
          useValue: options,
        },
        this.createRedisProvider(),
        AuthKitService,
        AuthKitGuard,
        RoleGuard,
      ],
      exports: [
        AuthKitService,
        AuthKitGuard,
        RoleGuard,
        JwtModule,
        'REDIS_CLIENT',
        AUTH_KIT_OPTIONS,
      ],
    };
  }

  static forRootAsync(options: AuthKitModuleAsyncOptions): DynamicModule {
    return {
      module: AuthKitModule,
      imports: [JwtModule.register({})],
      providers: [
        ...this.createAsyncProviders(options),
        this.createRedisProvider(),
        AuthKitService,
        AuthKitGuard,
        RoleGuard,
      ],
      exports: [
        AuthKitService,
        AuthKitGuard,
        RoleGuard,
        JwtModule,
        'REDIS_CLIENT',
        AUTH_KIT_OPTIONS,
      ],
    };
  }

  private static createAsyncProviders(options: AuthKitModuleAsyncOptions): Provider[] {
    if (options.useFactory || options.useExisting) {
      return [this.createAsyncOptionsProvider(options)];
    }
    return [
      this.createAsyncOptionsProvider(options),
      {
        provide: options.useClass,
        useClass: options.useClass,
      },
    ];
  }

  private static createAsyncOptionsProvider(options: AuthKitModuleAsyncOptions): Provider {
    if (options.useFactory) {
      return {
        provide: AUTH_KIT_OPTIONS,
        useFactory: async (...args: any[]) => {
          const config = await options.useFactory(...args);
          this.validateOptions(config);
          return config;
        },
        inject: options.inject || [],
      };
    }
    return {
      provide: AUTH_KIT_OPTIONS,
      useFactory: async (optionsFactory: AuthKitOptionsFactory) => {
        const config = await optionsFactory.createAuthKitOptions();
        this.validateOptions(config);
        return config;
      },
      inject: [options.useExisting || options.useClass],
    };
  }

  private static validateOptions(options: AuthKitOptions) {
    if (!options.jwt?.accessSecret || !options.jwt?.refreshSecret) {
      throw new Error('AuthKit Error: accessSecret and refreshSecret are required.');
    }
  }

  private static createRedisProvider(): Provider {
    return {
      provide: 'REDIS_CLIENT',
      useFactory: (options: AuthKitOptions) => {
        return new Redis({
          host: options.redis.host,
          port: options.redis.port,
          password: options.redis.password,
        });
      },
      inject: [AUTH_KIT_OPTIONS],
    };
  }
}