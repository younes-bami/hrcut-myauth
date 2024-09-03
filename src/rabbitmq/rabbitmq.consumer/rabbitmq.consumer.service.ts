import { Injectable, OnModuleInit, Logger, InternalServerErrorException } from '@nestjs/common';
import * as amqp from 'amqplib';
import { AuthService } from '../../auth/auth.service';
import { UpdateUserDto } from '../../auth/dto/update-user.dto';

@Injectable()
export class RabbitMQConsumerService implements OnModuleInit {
  private readonly logger = new Logger(RabbitMQConsumerService.name);
  private connection!: amqp.Connection;
  private channel!: amqp.Channel;
  private readonly exchange = 'customer_exchange';
  private readonly queue = 'customer_update_queue';
  private readonly routingKey = 'update_customer';

  // Define DLX and DLQ
  private readonly updateCustomerDeadLetterExchange = 'update_customer_dl_exchange';
  private readonly updateCustomerDeadLetterQueue = 'update_customer_dl_queue';

  constructor(private readonly authService: AuthService) {}

  async onModuleInit() {
    try {
      this.connection = await amqp.connect('amqp://guest:guest@localhost:5672');
      this.channel = await this.connection.createChannel();

      // Create and bind the Dead Letter Exchange and Queue
      await this.channel.assertExchange(this.updateCustomerDeadLetterExchange, 'direct', { durable: true });
      await this.channel.assertQueue(this.updateCustomerDeadLetterQueue, { durable: true });
      await this.channel.bindQueue(this.updateCustomerDeadLetterQueue, this.updateCustomerDeadLetterExchange, this.routingKey);

      // Configure the main queue with a DLX
      await this.channel.assertQueue(this.queue, {
        durable: true,
        deadLetterExchange: this.updateCustomerDeadLetterExchange,
        deadLetterRoutingKey: this.routingKey,
      });

      await this.channel.bindQueue(this.queue, this.exchange, this.routingKey);

      await this.channel.consume(this.queue, async (msg) => {
        if (msg !== null) {
          const messageContent = msg.content.toString();
          this.logger.log(`Received message: ${messageContent}`);
          try {
            const { data } = JSON.parse(messageContent);
            const { authUserId, ...updateUserData } = data;

            if (authUserId) {
              this.logger.log('Processing the update for user');
              await this.authService.updateUserByAuthId(authUserId, updateUserData as UpdateUserDto);
              this.logger.log('User updated successfully');
              this.channel.ack(msg);
            } else {
              throw new Error('authUserId is missing in the message');
            }
          } catch (error) {
            this.logger.error(`Failed to update User : ${messageContent}`, (error as Error).stack);
            this.channel.nack(msg, false, false); // Send to DLQ after rejecting
          }
        }
      }, { noAck: false });

      this.logger.log('RabbitMQ consumer connected and listening for messages');
    } catch (error) {
      this.logger.error('Failed to connect to RabbitMQ', (error as Error).stack);
      throw new InternalServerErrorException('Failed to connect to RabbitMQ');
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
