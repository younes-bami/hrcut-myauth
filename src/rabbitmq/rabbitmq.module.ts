import { Module, Global } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { RabbitMQProdcuerService } from './rabbitmq.producer/rabbitmq.producer.service';
import { RabbitMQConsumerService } from './rabbitmq.consumer/rabbitmq.consumer.service';
import { AuthModule } from '../auth/auth.module';

@Global()  // <-- Marking the module as global
@Module({
  imports: [ConfigModule,AuthModule],
  providers: [RabbitMQProdcuerService,RabbitMQConsumerService],
  exports: [RabbitMQProdcuerService,RabbitMQConsumerService],
})
export class RabbitMQModule {}
