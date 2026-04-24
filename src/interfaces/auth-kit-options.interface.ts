// src/interfaces/auth-kit-options.interface.ts
export interface AuthKitOptions {
  jwt: {
    accessSecret: string;
    refreshSecret: string;
    accessTtl: string;  // e.g., '15m'
    refreshTtl: string; // e.g., '7d'
    algorithm?: 'HS256' | 'HS384' | 'HS512' | 'RS256';
  };
  redis: {
    host: string;
    port: number;
    password?: string;
  };
  twoFactor?: {
    enabled: boolean;
    appName: string; // Used for Google Authenticator display
  };
}

export interface AuthKitOptionsFactory {
  createAuthKitOptions(): Promise<AuthKitOptions> | AuthKitOptions;
}

export interface AuthKitModuleAsyncOptions {
  useExisting?: any;
  useClass?: any;
  useFactory?: (...args: any[]) => Promise<AuthKitOptions> | AuthKitOptions;
  inject?: any[];
}