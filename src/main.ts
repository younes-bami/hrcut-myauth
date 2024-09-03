import { NestFactory } from '@nestjs/core';
import { AppModule } from './main/app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import * as dotenv from 'dotenv';
import { ValidationPipe, Logger } from '@nestjs/common';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';

dotenv.config();

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const logger = new Logger('Bootstrap');

  const config = new DocumentBuilder()
    .setTitle('Auth Service')
    .setDescription('API documentation for the Auth Service')
    .setVersion('1.0')
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
      },
      'access-token',
    )
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api-docs', app, document);

  //const microservice = await NestFactory.createMicroservice<MicroserviceOptions>(AppModule, {});
  //await microservice.listen();

  app.enableCors();
  //app.useGlobalPipes(new ValidationPipe());
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,  // Strips out properties that are not in the DTO
    forbidNonWhitelisted: true,  // Throws an error if unknown properties are present
    transform: true,  // Automatically transforms the payloads to be objects typed according to their DTO classes
  })); 
  await app.listen(3001); // Port dédié pour le auth-service
}
bootstrap();
