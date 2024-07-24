import { Injectable, OnModuleInit, OnModuleDestroy, Logger, InternalServerErrorException } from '@nestjs/common';
import { ClientProxy, ClientProxyFactory, Transport, ClientOptions } from '@nestjs/microservices';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class RabbitMQService implements OnModuleInit, OnModuleDestroy {
  private client: ClientProxy;
  private readonly logger = new Logger(RabbitMQService.name);

  constructor(private readonly configService: ConfigService) {
    this.client = this.createClient();
  }

  onModuleInit() {
    this.logger.log('RabbitMQ client initialized successfully');
  }

  onModuleDestroy() {
    try {
      if (this.client) {
        this.client.close();
        this.logger.log('RabbitMQ client closed successfully');
      }
    } catch (error) {
      this.logger.error('Failed to close RabbitMQ client', error);
    }
  }

  emit(pattern: string, data: any) {
    try {
      this.logger.log(`Emitting message with pattern: ${pattern} and data: ${JSON.stringify(data)}`);
      return this.client.emit(pattern, data);
    } catch (error) {
      this.logger.error('Failed to emit message', error);
      throw new InternalServerErrorException('Failed to emit message');
    }
  }

  private createClient(): ClientProxy {
    const rabbitmqUrl = this.configService.get<string>('RABBITMQ_URL');
    if (!rabbitmqUrl) {
      throw new InternalServerErrorException('RABBITMQ_URL is not defined in the configuration');
    }

    const clientOptions: ClientOptions = {
      transport: Transport.RMQ,
      options: {
        urls: [rabbitmqUrl],
        queue: 'customer_queue',
        queueOptions: {
          durable: false,
        },
      },
    };

    return ClientProxyFactory.create(clientOptions);
  }
}
