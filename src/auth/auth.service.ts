import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import * as crypto from 'crypto';
import { SupabaseService } from '../supabase/supabase.service';
import { LoginDto } from '../auth/dto/login.dto';

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

function sha256(input: string) {
  return crypto.createHash('sha256').update(input).digest('hex');
}


function getIp(req?: any): string | null {
  if (!req) return null;
  const xf = req.headers?.['x-forwarded-for'];
  if (typeof xf === 'string' && xf.length) return xf.split(',')[0].trim();
  return req.ip || req.socket?.remoteAddress || null;
}

function getBrowser(req?: any): string | null {
  if (!req) return null;
  return req.headers?.['user-agent'] || null;
}

@Injectable()
export class AuthService {
  constructor(
    private readonly supabaseService: SupabaseService,
    private readonly jwtService: JwtService,
  ) {}

  async login(loginDto: LoginDto, req?: any) {
    const supabase = this.supabaseService.getClient();
    const { identifier, password } = loginDto;
    const rememberMe = !!loginDto.rememberMe;

    // escape quotes for supabase .or() string
    const safeIdentifier = identifier.replaceAll('"', '\\"');

    const { data: user, error } = await supabase
      .from('user_profile')
      .select('user_id, company_id, role_id, password_hash, email, username')
      .or(`email.eq."${safeIdentifier}",username.eq."${safeIdentifier}"`)
      .maybeSingle<UserRow>();

    if (error) throw new UnauthorizedException('Login failed');
    if (!user) throw new UnauthorizedException('User not found');
    //if (!user.is_active) throw new UnauthorizedException('Account inactive');
    if (!user.password_hash) throw new UnauthorizedException('No password set');

    const isMatch = await bcrypt.compare(password, user.password_hash);

    // log failed login 
    if (!isMatch) {
      await supabase.from('login_history').insert({
        login_id: crypto.randomUUID(),
        role_id: String(user.role_id), // your schema uses varchar
        user_id: user.user_id, // your schema uses varchar
        ip_address: getIp(req),
        browser_info: getBrowser(req),
        status: 'FAILED',
      });

      throw new UnauthorizedException('Invalid credentials');
    }

    // role_name
    const { data: roleRow, error: roleError } = await supabase
      .from('role')
      .select('role_name')
      .eq('role_id', user.role_id)
      .single();

    if (roleError || !roleRow) throw new UnauthorizedException('Role not found');

    // company_name
    const { data: companydb, error: companyError } = await supabase
      .from('company')
      .select('company_name')
      .eq('company_id', user.company_id)
      .single();

    if (companyError || !companydb)
      throw new UnauthorizedException('Company not found');

    //  Create login_id + session_id for audit trail
    const login_id = crypto.randomUUID();
    const session_id = crypto.randomUUID();

    // log successful login
    await supabase.from('login_history').insert({
      login_id,
      role_id: String(user.role_id), // varchar in your table
      user_id: user.user_id,
      ip_address: getIp(req),
      browser_info: getBrowser(req),
      status: 'SUCCESS',
    });

    // Access token payload (laman ng dapat info na kailangan sa access token, rest sa refresh token)
    const accessPayload = {
      type: 'access',
      sub_userid: user.user_id,
      company_id: user.company_id,
      role_id: user.role_id,
      role_name: roleRow.role_name,
      company_name: companydb.company_name,
    };

    const access_token = await this.jwtService.signAsync(accessPayload, {
      expiresIn: '15s',
    });

    // LONG refresh token (varies by rememberMe)
    // include login_id + session_id + role_id so logout can write logout_history
    const refresh_token = await this.jwtService.signAsync(
      {
        type: 'refresh',
        sub_userid: user.user_id,
        role_id: user.role_id,
        login_id,
        session_id,
      },
      { expiresIn: rememberMe ? '30d' : '7d' },
    );

    // store refresh session (hashed)
    const decoded: any = this.jwtService.decode(refresh_token);
    const expires_at = new Date(decoded.exp * 1000).toISOString();

    const token_hash = sha256(refresh_token);

    await supabase.from('refresh_session').insert({
      user_id: user.user_id,
      token_hash,
      expires_at,
    });

    return { access_token, refresh_token };
  }

  async logout(refreshToken: string, req?: any) {
    const supabase = this.supabaseService.getClient();

    let decoded: any;

    try {
      decoded = await this.jwtService.verifyAsync(refreshToken);
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const token_hash = sha256(refreshToken);

    // 1️Revoke refresh token
    await supabase
      .from('refresh_session')
      .update({ revoked_at: new Date().toISOString() })
      .eq('user_id', decoded.sub_userid)
      .eq('token_hash', token_hash);

    // Insert logout history (linked to login_id if available)
    await supabase.from('logout_history').insert({
      logout_id: crypto.randomUUID(),
      login_id: decoded.login_id ?? null,
      role_id: decoded.role_id != null ? String(decoded.role_id) : null, // varchar schema
      user_id: decoded.sub_userid ?? null,
      session_id: decoded.session_id ?? token_hash, // fallback
      ip_address: getIp(req),
      browser_info: getBrowser(req),
    });

    // 2️ Get username from user_profile
    const { data: user, error } = await supabase
      .from('user_profile')
      .select('username')
      .eq('user_id', decoded.sub_userid)
      .single();

    if (error || !user) {
      throw new UnauthorizedException('User not found');
    }

    return {
      message: 'Logged out',
      username: user.username,
    };
  }

  //  NEW: refresh endpoint logic
  async refresh(refreshToken: string) {
    const supabase = this.supabaseService.getClient();

    let decoded: any;
    try {
      decoded = await this.jwtService.verifyAsync(refreshToken);
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }

    if (decoded.type !== 'refresh') {
      throw new UnauthorizedException('Invalid refresh token type');
    }

    const userId = decoded.sub_userid;
    const token_hash = sha256(refreshToken);

    const { data: session, error } = await supabase
      .from('refresh_session')
      .select('expires_at, revoked_at')
      .eq('user_id', userId)
      .eq('token_hash', token_hash)
      .maybeSingle();

    if (error || !session) throw new UnauthorizedException('Session not found');
    if (session.revoked_at) throw new UnauthorizedException('Session revoked');
    if (new Date(session.expires_at) <= new Date())
      throw new UnauthorizedException('Session expired');

    // load user (fresh)
    const { data: user, error: userErr } = await supabase
      .from('user_profile')
      .select('user_id, company_id, role_id')
      .eq('user_id', userId)
      .single();

    if (userErr || !user) throw new UnauthorizedException('User not found');
    //if (!user.is_active) throw new UnauthorizedException('Account inactive');

    const { data: roleRow } = await supabase
      .from('role')
      .select('role_name')
      .eq('role_id', user.role_id)
      .single();

    const { data: companydb } = await supabase
      .from('company')
      .select('company_name')
      .eq('company_id', user.company_id)
      .single();

    const accessPayload = {
      type: 'access',
      sub_userid: user.user_id,
      company_id: user.company_id,
      role_id: user.role_id,
      role_name: roleRow?.role_name,
      company_name: companydb?.company_name,
    };

    const access_token = await this.jwtService.signAsync(accessPayload, {
      expiresIn: '15s',
    });

    return { access_token };
  }

  async me(accessToken: string) {
    try {
      const decoded: any = await this.jwtService.verifyAsync(accessToken);

      const supabase = this.supabaseService.getClient();

      const userId = decoded.sub_userid;
      if (!userId) throw new UnauthorizedException('Invalid token payload');

      const { data: user, error } = await supabase
        .from('user_profile')
        .select('user_id, email, username, employee_id, company_id, role_id')
        .eq('user_id', userId)
        .maybeSingle<UserRow>();

      if (error || !user) throw new UnauthorizedException('User not found');
      //if (!user.is_active) throw new UnauthorizedException('Account inactive');

      return {
        user_id: user.user_id,
        email: user.email,
        username: user.username,
        employee_id: user.employee_id,
        company_id: user.company_id,
        role_id: user.role_id,
        role_name: decoded.role_name,
      };
    } catch {
      throw new UnauthorizedException('Invalid token');
    }
  }
}