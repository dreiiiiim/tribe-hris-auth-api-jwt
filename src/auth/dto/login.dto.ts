

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



import { IsNotEmpty, IsString, MinLength, IsBoolean} from 'class-validator';

export class LoginDto {

  @IsString()
  @IsNotEmpty()
  identifier: string; // email OR username OR employee_id

  @IsString()
  @MinLength(6)
  password: string;

  @IsBoolean()
  rememberMe?: boolean; // true = long refresh token lifetime


}

