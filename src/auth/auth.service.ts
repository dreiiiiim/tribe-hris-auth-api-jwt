import { Injectable, BadRequestException, UnauthorizedException } from '@nestjs/common';
import { SupabaseService } from '../supabase/supabase.service';
import { LoginDto } from './dto/login.dto';



//main logic na call from controllers
@Injectable()
export class AuthService {
  constructor(private readonly supabaseService: SupabaseService) {}

  // LOGIN (identifier can be email or username hindi name kasi di unique yon)
  // LOGIN (identifier can be email or username)
async login(loginDto: LoginDto) {
  const supabase = this.supabaseService.getClient();

  // Step 1: Resolve identifier -> email
  const email = await this.findEmail(loginDto.identifier);

  // Step 2: Login via Supabase Auth (email + password)
  const { data, error } = await supabase.auth.signInWithPassword({
    email,
    password: loginDto.password,
  });

  if (error || !data.user || !data.session) {
    throw new UnauthorizedException(error?.message || 'Invalid credentials');
  }

  return {
    message: 'Login success',
    access_token: data.session.access_token,
    refresh_token: data.session.refresh_token,
    user: {
      id: data.user.id,
      email: data.user.email,
    },
    role: '', // placeholder until schema ready
  };
}


// ME (validate token and return basic user info)
async me(accessToken: string) {
  const supabase = this.supabaseService.getClient();

  const { data, error } = await supabase.auth.getUser(accessToken);

  if (error || !data.user) {
    throw new UnauthorizedException(error?.message || 'Invalid token');
  }

  return {
    id: data.user.id,
    email: data.user.email,
  };
}


// Helper: resolve username → email
private async findEmail(identifier: string): Promise<string> {
  const supabase = this.supabaseService.getClient();

  // If already email
  if (identifier.includes('@')) return identifier;

  // Query profiles table for username
  const { data, error } = await supabase
    .from('profiles')
    .select('email')
    .eq('username', identifier)
    .single();
    //Go to the profiles table, find the row where username equals the identifier, and return the email column. Expect exactly one result.
  if (error || !data?.email) {
    throw new UnauthorizedException('Invalid credentials');
  }

  return data.email;
}


  
}

