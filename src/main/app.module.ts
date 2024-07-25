import { Module,MiddlewareConsumer,RequestMethod } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthModule } from '../auth/auth.module';
import { APP_FILTER, APP_INTERCEPTOR } from '@nestjs/core';
import { HttpExceptionFilter } from '../common/filters/http-exception.filter';
import { ComponentInterceptor } from '../common/interceptors/component.interceptor';
import { LoggingMiddleware } from '../common/middleware/logging.middleware';
import { RabbitMQModule } from '../rabbitmq/rabbitmq.module'; // Import du module RabbitMQ
import { RabbitMQService } from '../rabbitmq/rabbitmq.service'; // Import du service RabbitMQ


@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    MongooseModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => {
        const uri = configService.get<string>('MONGODB_URI');
        return {
          uri,
        };
      },
      inject: [ConfigService],
    }),
    AuthModule,
    RabbitMQModule, // Ajout du module RabbitMQ

  ],
  providers: [
    {
      provide: APP_FILTER,
      useClass: HttpExceptionFilter,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: ComponentInterceptor,
    },
    RabbitMQService,
  ],
  exports: [RabbitMQService],
})
export class AppModule {
   configure(consumer: MiddlewareConsumer) {
     consumer
       .apply(LoggingMiddleware)
       .forRoutes({ path: '*', method: RequestMethod.ALL });
   }
 }
