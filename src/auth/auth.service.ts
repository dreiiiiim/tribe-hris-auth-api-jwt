import { Injectable, BadRequestException, UnauthorizedException } from '@nestjs/common';
import { SupabaseService } from '../supabase/supabase.service';
import { LoginDto } from './dto/login.dto';



//main logic na call from controllers
@Injectable()
export class AuthService {
  constructor(private readonly supabaseService: SupabaseService) {}

  // LOGIN (identifier can be email or username)
  async login(dto: LoginDto) {
    const supabase = this.supabaseService.getClient();

    // Step 1: Resolve identifier -> email
    const email = await this.resolveEmail(dto.identifier);

    // Step 2: Login via Supabase Auth (email + password)
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password: dto.password,
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
      // placeholder role habang wala pa schema
      role: '',
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

  // helper: supports email now; username later when schema is ready
  private async resolveEmail(identifier: string): Promise<string> {
    // if it contains '@', assume it's an email
    if (identifier.includes('@')) return identifier;

    // TODO: once DB schema is available:
    // query profiles table: select email where username = identifier
    // then return that email

    throw new UnauthorizedException(
      'Username login not available yet. Please login using email for now.',
    );
  }



  
}

