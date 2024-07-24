export interface JwtPayload {
  sub: string;            // User ID
  username: string;
  email: string;
  roles: string[];
  iat?: number;           // Issued at timestamp
  exp?: number;           // Expiration timestamp
  jti?: string;           // JWT ID
  permissions?: string[]; // Specific permissions
  aud?: string[];           // Audience
  iss?: string;           // Issuer
  phoneNumber: string; // Ajout du numéro de téléphone

}
