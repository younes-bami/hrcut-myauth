import { IsString, IsEmail, IsNotEmpty, IsOptional, MinLength, Matches } from 'class-validator';
import { IsMoroccanPhoneNumber } from './custom-validators';
import { ApiProperty } from '@nestjs/swagger';
import { Transform } from 'class-transformer';


export class RegisterUserDto {
  @ApiProperty({ example: 'john_doe' })
  @IsString()
  @IsNotEmpty()
  @Transform(({ value }) => value.trim()) // Supprime les espaces en début et en fin
  username!: string;

  @ApiProperty({
    example: 'P@ssw0rd!',
    description: 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number.',
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  @Matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$/, { message: 'Password too weak' })
  password!: string;

  @ApiProperty({ example: 'john.doe@example.com' })
  @IsEmail()
  @IsNotEmpty()
  @Transform(({ value }) => value.toLowerCase().trim()) // Convertit en minuscule et supprime les espaces
  email!: string;

  @ApiProperty({ example: '+212600000000' })
  @IsString()
  @IsNotEmpty()
  @IsMoroccanPhoneNumber()
  @Transform(({ value }) => value.trim()) // Supprime les espaces
  phoneNumber!: string;

  @ApiProperty({ example: 'John', required: false })
  @IsString()
  @IsOptional()  @
  Transform(({ value }) => value.trim()) // Supprime les espaces
  firstName?: string;

  @ApiProperty({ example: 'Doe', required: false })
  @IsString()
  @IsOptional()
  @Transform(({ value }) => value.trim()) // Supprime les espaces
  lastName?: string;

  @ApiProperty({ example: ['Customer'], required: false })
  @IsOptional()
  @IsString({ each: true })
  roles?: string[]; // Ajouter les rôles ici, facultatif
}
