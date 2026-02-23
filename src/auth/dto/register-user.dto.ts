//SPRINT 2 FOR APPLICANTS CREATING ACCOUNT ETC
//DEFAULT ROLE IS APPLICANT


//ONLY ACCEPTS EMAIL AND PASSWORD FOR NOW, CAN BE CHANGED LATER IF NEEDED
import { IsEmail, IsString, MinLength } from 'class-validator';

export class RegisterDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(6)
  password: string;
}


