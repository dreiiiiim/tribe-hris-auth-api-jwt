import { Controller, Get } from '@nestjs/common';
import { AuthService } from './auth.service';


//receives the requests extracts data etc, body, params, header ganon and calls the right service and returns the response from service
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

   /* EXAMPLES
   
     GET/users
     GET/users/:id
     POST/users
     PATCH/users/:id
     DELETE/users/:id
    */

}