import { Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { OutboxDocument } from './schemas/outbox.schema';
import { RabbitMQService } from '../rabbitmq/rabbitmq.service';

@Injectable()
export class OutboxService {
  private readonly logger = new Logger(OutboxService.name);

  constructor(
    @InjectModel('Outbox') private readonly outboxModel: Model<OutboxDocument>,
    private readonly rabbitMQService: RabbitMQService,
  ) {}


  async processOutboxMessages(): Promise<void> {
    try {
      // Retrieve all pending messages
      const pendingMessages = await this.outboxModel.find({ status: 'PENDING' }).exec();

      // Log the number of messages to process
      this.logger.log(`Found ${pendingMessages.length} pending outbox messages`);


      // Process each message one by one
      for (const message of pendingMessages) {
        try {
          // Send the message
          this.logger.log(`Processing message: ${message._id}`);
          await this.rabbitMQService.sendMessage(message.eventType, message.payload);

          // Update status to 'PROCESSED'
          await this.outboxModel.updateOne(
            { _id: message._id },
            { status: 'PROCESSED' }
          );

          // Log successful processing
          this.logger.log(`Message processed and marked as PROCESSED: ${message._id}`);
        } catch (error) {
            this.logger.error(`Failed to process outbox messages ${message._id} . Error: ${error instanceof Error ? error.stack : 'Unknown error occurred.'}`);
            // You can optionally implement retry logic here if needed
        }
      }
    } catch (error) {
      this.logger.error(`Failed to process outbox messages, rolling back transaction. Error: ${error instanceof Error ? error.stack : 'Unknown error occurred.'}`);
    }
  }
}


