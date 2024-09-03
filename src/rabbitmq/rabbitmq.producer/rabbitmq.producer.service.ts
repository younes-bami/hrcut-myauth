import { Injectable, Logger, OnModuleInit, InternalServerErrorException } from '@nestjs/common';
import * as amqp from 'amqplib';
import { RegisterUserDto } from '../../auth/dto/register-user.dto';
import * as mongoose from 'mongoose'; // For generating unique message IDs

@Injectable()
export class RabbitMQProdcuerService implements OnModuleInit {
  private readonly logger = new Logger(RabbitMQProdcuerService.name);
  private connection!: amqp.Connection;
  private channel!: amqp.Channel;
  private readonly exchange = 'customer_exchange';
  private readonly queue = 'customer_create_queue';
  private readonly routingKey = 'create_customer';

  // Define DLX and DLQ
  private readonly createCustomerDeadLetterExchange = 'create_customer_dl_exchange';
  private readonly createCustomerDeadLetterQueue = 'create_customer_dl_queue';

  async onModuleInit() {
    try {
      this.connection = await amqp.connect('amqp://guest:guest@localhost:5672');
      this.channel = await this.connection.createChannel();

      // Create and bind the Dead Letter Exchange and Queue
      await this.channel.assertExchange(this.createCustomerDeadLetterExchange, 'direct', { durable: true });
      await this.channel.assertQueue(this.createCustomerDeadLetterQueue, { durable: true });
      await this.channel.bindQueue(this.createCustomerDeadLetterQueue, this.createCustomerDeadLetterExchange, this.routingKey);

      // Configure the main queue with a DLX
      await this.channel.assertQueue(this.queue, {
        durable: true,
        deadLetterExchange: this.createCustomerDeadLetterExchange, // Attach DLX to the queue
        deadLetterRoutingKey: this.routingKey,
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
      const { password, ...dataWithoutPassword } = data; // Exclude the password from the message
      const message = JSON.stringify({ pattern, data: dataWithoutPassword });

      // Generate a unique messageId using MongoDB's ObjectId
      const messageId = new mongoose.Types.ObjectId().toString();

      this.logger.log(`Sending message: ${pattern} with data: ${message} and messageId: ${messageId}`);

      await this.channel.publish(this.exchange, this.routingKey, Buffer.from(message), {
        persistent: true,
        messageId: messageId, // Set the messageId in the message properties
      });

      this.logger.log('Message sent successfully');
    } catch (error) {
      this.logger.error('Failed to send message', error);
      throw new InternalServerErrorException('Failed to send message');
    }
  }

  async onModuleDestroy() {
    try {
      if (this.channel) {
        await this.channel.close();
      }
      if (this.connection) {
        await this.connection.close();
      }
      this.logger.log('RabbitMQ connection closed');
    } catch (error) {
      this.logger.error('Failed to close RabbitMQ connection', error);
    }
  }
}
