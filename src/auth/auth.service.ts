import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { SupabaseService } from '../supabase/supabase.service';
import { LoginDto } from './dto/login.dto';

type UserRow = {
  user_id: string;
  company_id: string;
  role_id: number;
  email: string;
  username: string | null;
  employee_id: string | null;
  password_hash: string | null;
  is_active: boolean;
};


// create table public.user_profile (
//   user_id uuid not null default gen_random_uuid (),
//   role_id integer not null,
//   company_id uuid not null,
//   employee_id character varying null,
//   first_name character varying not null,
//   last_name character varying not null,
//   email character varying not null,
//   is_first_login boolean null default true,
//   username character varying null,
//   password_hash character varying null,
//   is_active boolean null default true,
//   constraint user_profile_pkey primary key (user_id),
//   constraint user_profile_company_email_unique unique (company_id, email), // unique per company but can have same email in different companies (for multi-tenant)
//   constraint user_profile_company_employee_unique unique (company_id, employee_id), // unique per company but can have same employee_id in different companies (for multi-tenant)
//   constraint user_profile_company_username_unique unique (company_id, username),
//   constraint user_profile_company_id_fkey foreign KEY (company_id) references company (company_id) on delete CASCADE,
//   constraint user_profile_role_id_fkey foreign KEY (role_id) references role (role_id) on delete RESTRICT
// ) TABLESPACE pg_default;


@Injectable()
export class AuthService {
  constructor(
    private readonly supabaseService: SupabaseService,
    private readonly jwtService: JwtService,
  ) {}

async login(loginDto: LoginDto) {
  const supabase = this.supabaseService.getClient();
  const { identifier, password } = loginDto;

  // escape quotes for supabase .or() string
  // email and username are globally unique, no need for company id
  // employee_id removed as identifier since it's only unique per company
  
  const safeIdentifier = identifier.replaceAll('"', '\\"');

  const { data: user, error } = await supabase
    .from('user_profile')
    .select(
      'user_id, company_id, role_id, password_hash, email, username',
    )
    .or(
      `email.eq."${safeIdentifier}",username.eq."${safeIdentifier}"`,
    )
    .maybeSingle<UserRow>();

  if (error) throw new UnauthorizedException('Login failed');
  if (!user) throw new UnauthorizedException('User not found');
  //if (!user.is_active) throw new UnauthorizedException('Account inactive');
  if (!user.password_hash) throw new UnauthorizedException('No password set');

  const isMatch = await bcrypt.compare(password, user.password_hash);
  if (!isMatch) throw new UnauthorizedException('Invalid credentials');

  // fetch role_name for token (for RolesGuard)
  const { data: roleRow, error: roleError } = await supabase // getting role name from role table using role id from user table for token payload
    .from('role')
    .select('role_name')
    .eq('role_id', user.role_id)
    .single();

  if (roleError || !roleRow) {
    throw new UnauthorizedException('Role not found');
  }

  const { data: companydb, error: companyError } = await supabase //getting info from table using company id from user table to get company name for token payload
    .from('company')
    .select('company_name')
    .eq('company_id', user.company_id)
    .single();

  if (companyError || !companydb) {
    throw new UnauthorizedException('Company not found');
  }

  const payload = { // ito ung info na hinanap sa taas para i-include sa JWT token
    sub_userid: user.user_id,
    company_id: user.company_id,
    role_id: user.role_id,
    role_name: roleRow.role_name,
    company_name: companydb.company_name,
  };

  return {
    access_token: await this.jwtService.signAsync(payload),
  };
}

  async me(accessToken: string) {
    try {
      const decoded = await this.jwtService.verifyAsync(accessToken);

      const supabase = this.supabaseService.getClient();

      // fetch the user by user_id from token (not by identifier) for security
      const { data: user, error } = await supabase
        .from('user_profile')
        .select('user_id, email, username, employee_id, company_id, role_id, is_active')
        .eq('user_id', decoded.sub) // ✅ correct: get the exact user
        .maybeSingle<UserRow>();

      if (error || !user) throw new UnauthorizedException('User not found');
      if (!user.is_active) throw new UnauthorizedException('Account inactive');


    


      return {
        user_id: user.user_id,
        email: user.email,
        username: user.username,
        employee_id: user.employee_id,
        company_id: user.company_id,
        role_id: user.role_id,
        role_name: decoded.role_name, // ✅ already in token
      };
    } catch {
      throw new UnauthorizedException('Invalid token');
    }
  }
}