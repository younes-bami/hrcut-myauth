import * as bcrypt from 'bcrypt';
import { Injectable, InternalServerErrorException, UnauthorizedException, NotFoundException, ConflictException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { JwtPayload } from './jwt-payload.interface';
import { User, UserDocument } from './schemas/user.schema';
import { RegisterUserDto } from './dto/register-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { createNotFoundError, createUnauthorizedError, createConflictError } from '../common/utils/error.utils';
import { RabbitMQService } from '../rabbitmq/rabbitmq.service';
import * as mongoose from 'mongoose';
import { lastValueFrom } from 'rxjs';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private readonly jwtService: JwtService,
    private readonly rabbitMQService: RabbitMQService,
  ) {}

  async register(registerUserDto: RegisterUserDto): Promise<User> {
    try {
      const { username, email, phoneNumber, password } = registerUserDto;
      const existingUser = await this.userModel.findOne({ $or: [{ username }, { email }, { phoneNumber }] }).exec();

      if (existingUser) {
        throw createConflictError('User already exists with provided email, username, or phone number');
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = new this.userModel({ ...registerUserDto, password: hashedPassword });

      // Attribuer automatiquement le rôle "Customer"
      newUser.roles = ['Customer'];
      const user = await newUser.save();

      // Envoyer un message au microservice Customer
      await this.rabbitMQService.sendMessage('create_customer',  { ...registerUserDto });


      return user;
    } catch (error: unknown) {
      if (error instanceof ConflictException) {
        throw error;
      }
      if (error instanceof Error) {
        throw new InternalServerErrorException(error.message);
      }
      throw new InternalServerErrorException('An unknown error occurred');
    }
  }

  async validateUser(username: string, pass: string): Promise<Omit<UserDocument, 'password'>> {
    try {
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
    } catch (error: unknown) {
      if (error instanceof NotFoundException || error instanceof UnauthorizedException) {
        throw error;
      }
      if (error instanceof Error) {
        throw new InternalServerErrorException(error.message);
      }
      throw new InternalServerErrorException('An unknown error occurred');
    }
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
    } catch (error: unknown) {
      if (error instanceof UnauthorizedException || error instanceof NotFoundException) {
        throw error;
      }
      if (error instanceof Error) {
        throw new InternalServerErrorException(error.message);
      }
      throw new InternalServerErrorException('An unknown error occurred');
    }
  }

  async validateToken(token: string): Promise<JwtPayload> {
    try {
      return this.jwtService.verify(token);
    } catch (error: unknown) {
      if (error instanceof Error) {
        throw createUnauthorizedError('Invalid token');
      }
      throw new InternalServerErrorException('An unknown error occurred');
    }
  }

  async validateUserByJwt(payload: JwtPayload): Promise<UserDocument> {
    try {
      const user = await this.userModel.findOne({ username: payload.username }).exec();

      if (!user) {
        throw createNotFoundError('User', payload.username);
      }

      return user;
    } catch (error: unknown) {
      if (error instanceof Error) {
        throw new InternalServerErrorException(error.message);
      }
      throw new InternalServerErrorException('An unknown error occurred');
    }
  }
}
