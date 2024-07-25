import { Injectable, OnModuleInit, OnModuleDestroy, Logger, InternalServerErrorException } from '@nestjs/common';
import { ClientProxy, ClientProxyFactory, Transport, RmqOptions } from '@nestjs/microservices';
import * as dotenv from 'dotenv';

dotenv.config();

@Injectable()
export class RabbitMQService {
  private client: ClientProxy;
  private readonly logger = new Logger(RabbitMQService.name);

  constructor() {
    this.client = ClientProxyFactory.create(this.getRmqOptions());
  }

  private getRmqOptions(): RmqOptions {
    return {
      transport: Transport.RMQ,
      options: {
        urls: ['amqp://user:password@localhost:5672'],
        queue: 'customer_queue',
        queueOptions: {
          durable: false,
        },
      },
    };
  }

  async sendMessage(pattern: string, data: any) {
    try {
      const message = JSON.stringify({ data });
      this.logger.log(`Sending message: ${pattern} with data: ${message}`);
      return this.client.emit(pattern, data).toPromise();
    } catch (error) {
      this.logger.error('Failed to emit message', error);
      throw new InternalServerErrorException('Failed to emit message');
    }
  }
}
