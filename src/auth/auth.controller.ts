import { Controller, Post, Body, InternalServerErrorException, BadRequestException, UnauthorizedException, ConflictException, NotFoundException, UseInterceptors } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterUserDto } from './dto/register-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { ApiBearerAuth, ApiTags, ApiOperation, ApiBody, ApiResponse } from '@nestjs/swagger';
import { createBadRequestError, createUnauthorizedError } from '../common/utils/error.utils';
import { Component } from '../common/decorators/component.decorator';
import { ComponentInterceptor } from '../common/interceptors/component.interceptor';
import { plainToClass } from 'class-transformer';
import { validate } from 'class-validator';

@ApiTags('auth')
@Controller('auth')
@Component('AuthController')
@UseInterceptors(ComponentInterceptor)
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @ApiOperation({ summary: 'Register a new user' })
  @ApiBody({ type: RegisterUserDto, description: 'The user registration data' })
  @ApiResponse({ status: 201, description: 'The user has been successfully registered.', schema: { example: { username: 'john_doe', email: 'john.doe@example.com', phoneNumber: '+212600000000', firstName: 'John', lastName: 'Doe', roles: ['Customer'] } } })
  @ApiResponse({ status: 400, description: 'Invalid input data.' })
  @Post('register')
  async register(@Body() registerUserDto: RegisterUserDto) {
    try {
      const sanitizedDto = plainToClass(RegisterUserDto, registerUserDto);
      const errors = await validate(sanitizedDto);
      if (errors.length > 0) {
        throw new BadRequestException('Validation failed');
      }
      return await this.authService.register(sanitizedDto);
    } catch (error) {
      if (error instanceof BadRequestException || error instanceof ConflictException) {
        throw error;
      }
      throw new InternalServerErrorException((error as Error).message);
    }
  }

  @ApiOperation({ summary: 'Login user' })
  @ApiBody({ type: LoginUserDto, description: 'The user login data' })
  @ApiResponse({ status: 200, description: 'Login successful.', schema: { example: { access_token: 'your-access-token' } } })
  @ApiResponse({ status: 401, description: 'Invalid credentials.' })
  @Post('login')
  async login(@Body() loginUserDto: LoginUserDto) {
    try {
      const sanitizedDto = plainToClass(LoginUserDto, loginUserDto);
      const errors = await validate(sanitizedDto);
      if (errors.length > 0) {
        throw new BadRequestException('Validation failed');
      }
      return await this.authService.login(sanitizedDto);
    } catch (error) {
      if (error instanceof UnauthorizedException || error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerErrorException((error as Error).message);
    }
  }

  @ApiOperation({ summary: 'Validate JWT token' })
  @ApiBody({ schema: { example: { token: 'your-jwt-token' } } })
  @ApiResponse({ status: 200, description: 'Token is valid.', schema: { example: { valid: true } } })
  @ApiResponse({ status: 401, description: 'Invalid token.' })
  @Post('validate-token')
  async validateToken(@Body('token') token: string) {
    try {
      return await this.authService.validateToken(token);
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw createUnauthorizedError('Invalid token');
      }
      throw new InternalServerErrorException((error as Error).message);
    }
  }
}
