import * as fs from 'fs';
import { ConfigService } from '@nestjs/config';
import { JwtModuleOptions } from '@nestjs/jwt';

export const createJwtOptions = (configService: ConfigService): JwtModuleOptions => {
  const privateKeyPath = configService.get<string>('JWT_PRIVATE_KEY');
  const publicKeyPath = configService.get<string>('JWT_PUBLIC_KEY');

  if (!privateKeyPath || !publicKeyPath) {
    throw new Error('Les chemins des clés JWT ne sont pas définis dans le fichier .env.');
  }

  return {
    privateKey: fs.readFileSync(privateKeyPath, 'utf8'),
    publicKey: fs.readFileSync(publicKeyPath, 'utf8'),
    signOptions: {
      algorithm: 'RS256',
      expiresIn: '1h',
      issuer: configService.get<string>('JWT_ISSUER', 'auth-service'),
      audience: configService.get<string>('JWT_AUDIENCE', 'my-app'),
    },
  };
};
