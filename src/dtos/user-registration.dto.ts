import { IsEmail, IsString, MinLength } from 'class-validator';

export class UserRegistrationDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(8)
  password: string;

  @IsString()
  role: string;
}
