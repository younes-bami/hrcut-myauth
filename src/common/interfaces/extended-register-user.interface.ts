import { RegisterUserDto } from '../../auth/dto/register-user.dto';

export interface ExtendedRegisterUser extends RegisterUserDto {
  authUserId: string;
}
