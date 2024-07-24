import * as bcrypt from 'bcrypt';
import { Injectable, InternalServerErrorException, UnauthorizedException, NotFoundException, ConflictException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { JwtPayload } from './jwt-payload.interface';
import { User, UserDocument } from './schemas/user.schema';
import { RegisterUserDto } from './dto/register-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { createNotFoundError, createUnauthorizedError, createConflictError } from './common/utils/error.utils';
import * as mongoose from 'mongoose';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private readonly jwtService: JwtService,
  ) {}

  async register(registerUserDto: RegisterUserDto): Promise<User> {
    const { username, email, phoneNumber, password } = registerUserDto;
    const existingUser = await this.userModel.findOne({ $or: [{ username }, { email }, { phoneNumber }] }).exec();

    if (existingUser) {
      throw createConflictError('User already exists with provided email, username, or phone number');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new this.userModel({ ...registerUserDto, password: hashedPassword });

    // Attribuer automatiquement le rôle "Customer"
    newUser.roles = ['Customer'];

    return newUser.save();
  }

  async validateUser(username: string, pass: string): Promise<Omit<UserDocument, 'password'>> {
    const user = await this.userModel.findOne({ username }).exec();

    if (!user) {
      throw createNotFoundError('User', username);
    }

    const isPasswordValid = await bcrypt.compare(pass, user.password);
    if (!isPasswordValid) {
      throw createUnauthorizedError('Invalid credentials');
    }

    const { password, ...result } = user.toObject();
    return result as Omit<UserDocument, 'password'>;
  }

  async login(loginUserDto: LoginUserDto): Promise<{ access_token: string }> {
    try {
      const user = await this.validateUser(loginUserDto.username, loginUserDto.password);
      const userId = (user._id as mongoose.Types.ObjectId).toString();
      const payload: Partial<JwtPayload> = {
        sub: userId,
        username: user.username,
        email: user.email,
        phoneNumber: user.phoneNumber,
        roles: user.roles,
      };

      return {
        access_token: this.jwtService.sign(payload, {
          expiresIn: '1h',
          issuer: 'auth-service',
          audience: ['customer-service', 'hairdress-service', 'booking-service'],
          jwtid: new mongoose.Types.ObjectId().toString(),
        }),
      };
    } catch (error) {
      if (error instanceof UnauthorizedException || error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerErrorException((error as Error).message);
    }
  }

  async validateToken(token: string): Promise<JwtPayload> {
    try {
      return this.jwtService.verify(token);
    } catch (error) {
      throw createUnauthorizedError('Invalid token');
    }
  }

  async validateUserByJwt(payload: JwtPayload): Promise<UserDocument> {
    const user = await this.userModel.findOne({ username: payload.username }).exec();

    if (!user) {
      throw createNotFoundError('User', payload.username);
    }

    return user;
  }
}
