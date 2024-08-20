import * as bcrypt from 'bcrypt';
import { Injectable, InternalServerErrorException, UnauthorizedException, NotFoundException, ConflictException, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { JwtPayload } from '../common/interfaces/jwt-payload.interface';
import { User, UserDocument } from './schemas/user.schema';
import { RegisterUserDto } from './dto/register-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { createNotFoundError, createUnauthorizedError, createConflictError } from '../common/utils/error.utils';
import { RabbitMQService } from '../rabbitmq/rabbitmq.service';
import * as mongoose from 'mongoose';
import { lastValueFrom } from 'rxjs';
import { ExtendedRegisterUser } from '../common/interfaces/extended-register-user.interface';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

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

        // Construire le message en utilisant ExtendedRegisterUser
        const message: ExtendedRegisterUser = {
          authUserId: user.id,
          ...registerUserDto,
       
        };
  
        // Envoyer un message au microservice Customer
        await this.rabbitMQService.sendMessage('create_customer', message);
  

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

  async login(loginUserDto: LoginUserDto): Promise<{ access_token: string; refresh_token: string }> {

    try {
        const user = await this.validateUser(loginUserDto.username, loginUserDto.password);
        const userId = (user._id as mongoose.Types.ObjectId).toString();

        // Définir les scopes en fonction du rôle de l'utilisateur
          let scopes: string[] = [];
          if (user.roles.includes('Customer')) {
          scopes = ['read:customer', 'write:customer'];
                                                }
          if (user.roles.includes('Admin')) {
          scopes = ['manage:all'];
                                            }
        const payload: Partial<JwtPayload> = {
            sub: userId,
            username: user.username,
            email: user.email,
            phoneNumber: user.phoneNumber,
            roles: user.roles,
            scopes: scopes,

        };
                // Payload minimal pour le refresh token
        const refreshPayload: Partial<JwtPayload> = {
            sub: userId,
            username: user.username,
            roles: user.roles,
            scopes: ['refresh_token'], // Scope spécifique pour le refresh token
              };

        // Génération de l'access token
        const access_token = this.jwtService.sign(payload, {
            expiresIn: '1h',
            issuer: 'auth-service',
            audience: ['auth-service', 'hairdress-service', 'booking-service'],
            jwtid: new mongoose.Types.ObjectId().toString(),
        });

        // Génération du refresh token
        const refresh_token = this.jwtService.sign(refreshPayload, {
            expiresIn: '7d',  // Durée de vie plus longue pour le refresh token
            issuer: 'auth-service',
            audience: ['customer-service', 'hairdress-service', 'booking-service'],
            jwtid: new mongoose.Types.ObjectId().toString(),
        });

        // Hash et stockage du refresh token
        const hashedRefreshToken = await bcrypt.hash(refresh_token, 10);
        await this.userModel.findByIdAndUpdate(user._id, { refreshToken: hashedRefreshToken });

        return {
            access_token,
            refresh_token,
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
      this.logger.log(`Validating token: ${token}`);
      const payload = this.jwtService.verify(token);
 
          // Vérifier si le token a été révoqué


      this.logger.log(`Token validated successfully: ${JSON.stringify(payload)}`);
      return payload;
    } catch (error: unknown) {
      this.logger.error('Invalid token', (error as Error).message);
      throw createUnauthorizedError('Invalid token');
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

  async refreshAccessToken(refreshToken: string): Promise<{ access_token: string, refresh_token: string }> {
    try {
        this.logger.debug(`Received refresh token: ${refreshToken}`);

        const payload = this.jwtService.verify(refreshToken);
        const user = await this.userModel.findOne({ username: payload.username }).exec();

  
        if (!user) {
            this.logger.error('User not found.');
            throw new UnauthorizedException('Invalid refresh token : User Not Found');
        }

        if (!user.refreshToken) {
            this.logger.error('No refresh token stored for user.');
            throw new UnauthorizedException('Invalid refresh token: No refresh token stored for user');
        }

        // Compare the provided refresh token with the stored hashed refresh token
        const isRefreshTokenValid = await bcrypt.compare(refreshToken, user.refreshToken);
        if (!isRefreshTokenValid) {
            this.logger.error('Invalid refresh token: Token comparison failed');
            throw new UnauthorizedException('Invalid refresh token: Token comparison failed');
        }


        // Définir les scopes en fonction du rôle de l'utilisateur
        let scopes: string[] = [];
        if (user.roles.includes('Customer')) {
        scopes = ['read:customer', 'write:customer'];
        }
        if (user.roles.includes('Admin')) {
        scopes = ['manage:all'];
        }

        const newPayload: Partial<JwtPayload> = {
            sub: user._id.toString(),
            username: user.username,
            email: user.email,
            phoneNumber: user.phoneNumber,
            roles: user.roles,
            scopes: scopes,
        };

        const newRefreshPayload: Partial<JwtPayload> = {
          sub: user._id.toString(),
          username: user.username,
          roles: user.roles,
          scopes: ['refresh_token'],
      };
        const accessToken = this.jwtService.sign(newPayload, {
            expiresIn: '1h',
            issuer: 'auth-service',
            audience: ['customer-service', 'hairdress-service', 'booking-service'],
            jwtid: new mongoose.Types.ObjectId().toString(),
        });

        const newRefreshToken = this.jwtService.sign(newRefreshPayload, {
            expiresIn: '7d',
            issuer: 'auth-service',
            jwtid: new mongoose.Types.ObjectId().toString(),
        });

        const hashedRefreshToken = await bcrypt.hash(newRefreshToken, 10);
        await this.userModel.findByIdAndUpdate(user._id, { refreshToken: hashedRefreshToken });

        return {
            access_token: accessToken,
            refresh_token: newRefreshToken,
        };
    } catch (error) {
        if (error instanceof UnauthorizedException) {
            throw error;
        }
        if (error instanceof Error) {
            throw new InternalServerErrorException(error.message);
        }
        throw new InternalServerErrorException('An unknown error occurred');
    }
}


  
}
