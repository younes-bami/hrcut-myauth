import * as bcrypt from 'bcrypt';
import { Injectable, InternalServerErrorException, UnauthorizedException, NotFoundException, ConflictException, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel,InjectConnection } from '@nestjs/mongoose';
import {Connection} from 'mongoose';
import { Model, Types } from 'mongoose';
import { JwtPayload } from '../common/interfaces/jwt-payload.interface';
import { User, UserDocument } from './schemas/user.schema';
import { RegisterUserDto } from './dto/register-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { createNotFoundError, createUnauthorizedError, createConflictError } from '../common/utils/error.utils';
import * as mongoose from 'mongoose';
import { lastValueFrom } from 'rxjs';
import { ExtendedRegisterUser } from '../common/interfaces/extended-register-user.interface';
import { OutboxDocument } from './schemas/outbox.schema';
import { UpdateUserDto } from './dto/update-user.dto';



@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    @InjectModel('Outbox') private outboxModel: Model<OutboxDocument>,  // Injecting the Outbox model
    @InjectConnection() private readonly connection: Connection,
    private readonly jwtService: JwtService,
  ) {}

  async register(registerUserDto: RegisterUserDto): Promise<User> {
    const session = await this.connection.startSession();
    session.startTransaction();
  
    this.logger.log('Transaction started for user registration');
  
    try {
      const { username, email, phoneNumber, password } = registerUserDto;
      this.logger.log(`Checking if user with username: ${username}, email: ${email}, or phoneNumber: ${phoneNumber} already exists`);
  
      const existingUser = await this.userModel.findOne({
        $or: [{ username }, { email }, { phoneNumber }],
      }).session(session).exec();
  
      if (existingUser) {
        this.logger.warn('User already exists, aborting registration');
        throw createConflictError('User already exists with provided email, username, or phone number');
      }
  
      this.logger.log('User does not exist, proceeding with registration');
  
      const hashedPassword = await bcrypt.hash(password, 10);
      this.logger.log('Password hashed successfully');
  
      const newUser = new this.userModel({ ...registerUserDto, password: hashedPassword });
      newUser.roles = ['Customer'];
      this.logger.log('New user created, saving to database');
  
      const user = await newUser.save({ session });
      this.logger.log(`User saved successfully: ${JSON.stringify(user)}`);
  
      // Writing the message to the Outbox
      this.logger.log('Creating outbox message');
      const outboxMessage = new this.outboxModel({
        eventType: 'create_customer',
        payload: {
          authUserId: user.id,
          ...registerUserDto,
        },
        status: 'PENDING',
      });
  
      this.logger.log('Saving outbox message');
      await outboxMessage.save({ session });
      this.logger.log('Outbox message saved successfully');
  
      await session.commitTransaction();
      this.logger.log('Transaction committed successfully');
  
      return user;
    } catch (error: unknown) {
      this.logger.error('Error during transaction, aborting', error);
      await session.abortTransaction();
      session.endSession();
  
      if (error instanceof ConflictException) {
        throw error;
      }
      if (error instanceof Error) {
        throw new InternalServerErrorException(error.message);
      }
      throw new InternalServerErrorException('An unknown error occurred');
    } finally {
      session.endSession();
      this.logger.log('Transaction session ended');
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

            // Vérification que le token a le bon scope pour être un refresh token
        if (!payload.scopes.includes('refresh_token')) {
          throw new UnauthorizedException('Invalid refresh token: Invalid token type');
        }


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


/**
   * Met à jour les informations d'un utilisateur basé sur authUserId.
   * @param authUserId - L'identifiant unique de l'utilisateur dans le service Auth.
   * @param updateUserDto - Les données de mise à jour.
   * @returns L'utilisateur mis à jour.
   * @throws NotFoundException si l'utilisateur n'est pas trouvé.
   * @throws ConflictException si l'email ou le numéro de téléphone est déjà utilisé.
   * @throws InternalServerErrorException pour les autres erreurs.
   */
async updateUserByAuthId(authUserId: string, updateUserDto: UpdateUserDto): Promise<User> {
  const session = await this.connection.startSession();
  session.startTransaction();

  this.logger.log(`Transaction started for updating user with authUserId: ${authUserId}`);

  try {
    const existingUser = await this.userModel.findById(authUserId).session(session).exec();

    if (!existingUser) {
      this.logger.warn(`User not found with authUserId: ${authUserId}`);
      throw createNotFoundError('User', authUserId);
    }

    // Vérifier les conflits d'email
    if (
      updateUserDto.email &&
      updateUserDto.email !== existingUser.email
    ) {
      const emailExists = await this.userModel.findOne({ email: updateUserDto.email }).session(session).exec();
      if (emailExists) {
        this.logger.warn(`Email already exists: ${updateUserDto.email}`);
        throw createConflictError('User avec cet email existe déjà');
      }
    }

    // Vérifier les conflits de numéro de téléphone
    if (
      updateUserDto.phoneNumber &&
      updateUserDto.phoneNumber !== existingUser.phoneNumber
    ) {
      const phoneNumberExists = await this.userModel.findOne({ phoneNumber: updateUserDto.phoneNumber }).session(session).exec();
      if (phoneNumberExists) {
        this.logger.warn(`Phone number already exists: ${updateUserDto.phoneNumber}`);
        throw createConflictError('User avec ce numéro de téléphone existe déjà');
      }
    }

    // Si le mot de passe est mis à jour, le hacher
    if (updateUserDto.password) {
      updateUserDto.password = await bcrypt.hash(updateUserDto.password, 10);
    }

    // Assignation des nouvelles valeurs depuis le DTO
    Object.assign(existingUser, updateUserDto);

    // Sauvegarder l'utilisateur mis à jour dans la session
    const updatedUser = await existingUser.save({ session });

    this.logger.log(`User updated successfully: ${JSON.stringify(updatedUser)}`);

    // Commit de la transaction
    await session.commitTransaction();
    this.logger.log('Transaction committed successfully');

    return updatedUser;
  } catch (error) {
    this.logger.error('Error updating user, aborting transaction', error);
    await session.abortTransaction();

    if (error instanceof NotFoundException || error instanceof ConflictException) {
      throw error;
    }

    if (error instanceof Error) {
      throw new InternalServerErrorException(error.message);
    }

    throw new InternalServerErrorException('Une erreur inconnue est survenue');
  } finally {
    session.endSession();
    this.logger.log(`Transaction session ended for authUserId: ${authUserId}`);
  }
}



}
