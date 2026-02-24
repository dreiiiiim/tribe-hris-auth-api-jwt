import { Controller, Post,  Body } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';


//receives the requests extracts data etc, body, params, header ganon and calls the right service and returns the response from service
@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

   /* EXAMPLES CRUD
   
     GET/users
     GET/users/:id
     POST/users
     PATCH/users/:id
     DELETE/users/:id
    */


     @Post('login')
     login(@Body() loginDto: LoginDto) {
       return this.authService.login(loginDto);
     }










}