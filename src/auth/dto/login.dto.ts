import { IsEmail, IsString, MinLength } from 'class-validator';

// Ito yung structure ng data na tatanggapin ng login endpoint.

//EMAIL ONLY FOR NOW, CAN BE CHANGED LATER IF NEEDED
// export class LoginDto {
//   @IsEmail()
//   email: string;

//   @IsString()
//   @MinLength(6)
//   password: string;
// }

// login.dto.ts


export class LoginDto {
  @IsString()
  identifier: string; // accepts either email or username

  @IsString()
  @MinLength(6)
  password: string;
}