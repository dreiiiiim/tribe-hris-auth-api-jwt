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

@Injectable()
export class AuthService {
  constructor(
    private readonly supabaseService: SupabaseService,
    private readonly jwtService: JwtService,
  ) {}

  async login(loginDto: LoginDto) {
    const supabase = this.supabaseService.getClient();
    const { companyId, identifier, password } = loginDto;

    // ✅ IMPORTANT: escape quotes in identifier to avoid breaking the .or() string
    const safeIdentifier = identifier.replaceAll('"', '\\"');

    const { data: user, error } = await supabase
      .from('user_profile')
      .select(
        'user_id, company_id, role_id, password_hash, is_active, email, username, employee_id',
      )
      .eq('company_id', companyId)
      .or(
        `email.eq."${safeIdentifier}",username.eq."${safeIdentifier}",employee_id.eq."${safeIdentifier}"`,
      )
      .maybeSingle<UserRow>(); // ✅ prevents throw when 0 rows

    if (error) {
      throw new UnauthorizedException('Login failed');
    }

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    if (!user.is_active) {
      throw new UnauthorizedException('Account inactive');
    }

    if (!user.password_hash) {
      throw new UnauthorizedException('No password set');
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const payload = {
      sub: user.user_id,
      company_id: user.company_id,
      role_id: user.role_id,
    };

    return {
      access_token: await this.jwtService.signAsync(payload),
    };
  }

  async me(accessToken: string) {
    try {
      const decoded = await this.jwtService.verifyAsync(accessToken);

      const supabase = this.supabaseService.getClient();
      const { data: user, error } = await supabase
        .from('user_profile')
        .select('user_id, email, username, employee_id, company_id, role_id, is_active')
        .eq('user_id', decoded.sub)
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
      };
    } catch {
      throw new UnauthorizedException('Invalid token');
    }
  }
}