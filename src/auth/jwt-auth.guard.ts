import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private readonly jwtService: JwtService) {}

  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest();

    const authHeader: string | undefined =
      req.headers['authorization'] || req.headers['Authorization'];

    if (!authHeader) {
      throw new UnauthorizedException('Missing Authorization header');
    }

    const [type, token] = authHeader.split(' ');
    if (type !== 'Bearer' || !token) {
      throw new UnauthorizedException('Invalid Authorization header format');
    }

      try {
      const decoded = this.jwtService.verify(token);

      //  BLOCK refresh tokens from accessing protected routes
      if (decoded.type !== 'access') {
        throw new UnauthorizedException('Access token required');
      }

      req.user = decoded;
      return true;
    } catch {
      throw new UnauthorizedException('Invalid token');
}
  }
}