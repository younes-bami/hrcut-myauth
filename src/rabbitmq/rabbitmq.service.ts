import { Injectable, Logger, OnModuleInit, InternalServerErrorException } from '@nestjs/common';
import * as amqp from 'amqplib';
import { RegisterUserDto } from '../auth/dto/register-user.dto';

@Injectable()
export class RabbitMQService implements OnModuleInit {
  private readonly logger = new Logger(RabbitMQService.name);
  private connection!: amqp.Connection;
  private channel!: amqp.Channel;
  private readonly exchange = 'customer_exchange';
  private readonly queue = 'customer_queue';
  private readonly routingKey = 'create_customer';

  async onModuleInit() {
    try {
      this.connection = await amqp.connect('amqp://guest:guest@localhost:5672');
      this.channel = await this.connection.createChannel();
      await this.channel.assertExchange(this.exchange, 'direct', {
        durable: true,
      });
      await this.channel.assertQueue(this.queue, {
        durable: true,
      });
      await this.channel.bindQueue(this.queue, this.exchange, this.routingKey);
      this.logger.log('Connected to RabbitMQ');
    } catch (error) {
      this.logger.error('Failed to connect to RabbitMQ', error);
      throw new InternalServerErrorException('Failed to connect to RabbitMQ');
    }
  }
  async sendMessage(pattern: string, data: RegisterUserDto) {
    try {
      const { password, ...dataWithoutPassword } = data; // Exclure le mot de passe
      const message = JSON.stringify({ pattern, data: dataWithoutPassword });
      this.logger.log(`Sending message: ${pattern} with data: ${message}`);
      await this.channel.publish(this.exchange, this.routingKey, Buffer.from(message), {
        persistent: true,
      });
      this.logger.log('Message sent successfully');
    } catch (error) {
      this.logger.error('Failed to send message', error);
      throw new InternalServerErrorException('Failed to send message');
    }
  }
}
