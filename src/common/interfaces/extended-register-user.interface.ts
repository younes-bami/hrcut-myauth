import { RegisterUserDto } from './dto/register-user.dto';

export interface ExtendedRegisterUser extends RegisterUserDto {
  authUserId: string;
}
