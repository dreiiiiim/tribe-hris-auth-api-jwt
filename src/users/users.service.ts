import { Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-users.dto';
import { UpdateUserDto } from './dto/update-user.dto';

@Injectable()
export class UsersService {
  findAll() {}

  findOne(id: string) {}

  create(dto: CreateUserDto) {}

  update(id: string, dto: UpdateUserDto) {}

  remove(id: string) {}
}
