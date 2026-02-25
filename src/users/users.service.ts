import { Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-users.dto';
import { UpdateUserDto } from './dto/update-user.dto';

//empty because sprint 1 abt login only 

// HERE YUNG
// Once you implement real features like:

// Admin creates user accounts

// Admin updates roles

// List users per company

// Delete users

@Injectable()
export class UsersService {
  findAll() {
    
  }

  

  findOne(id: string) {}

  create(dto: CreateUserDto) {}

  update(id: string, dto: UpdateUserDto) {}

  remove(id: string) {}
}
