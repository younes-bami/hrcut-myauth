import { Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, ClientSession } from 'mongoose';
import { OutboxDocument } from './schemas/outbox.schema';
import { RabbitMQProdcuerService } from '../rabbitmq/rabbitmq.producer/rabbitmq.producer.service';

@Injectable()
export class OutboxService {
  private readonly logger = new Logger(OutboxService.name);

  constructor(
    @InjectModel('Outbox') private readonly outboxModel: Model<OutboxDocument>,
    private readonly rabbitMQService: RabbitMQProdcuerService,
  ) {}

  async processOutboxMessages(): Promise<void> {
    const session: ClientSession = await this.outboxModel.db.startSession();

    try {
      // Start the session and transaction
      session.startTransaction();

      // Retrieve all pending messages
      const pendingMessages = await this.outboxModel.find({ status: 'PENDING' }).session(session).exec();

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
            { status: 'PROCESSED' },
            { session }
          );

          // Log successful processing
          this.logger.log(`Message processed and marked as PROCESSED: ${message._id}`);
        } catch (error) {
          this.logger.error(`Failed to process message ${message._id}. Error: ${error instanceof Error ? error.stack : 'Unknown error occurred.'}`);
          // Abort the transaction in case of failure
          await session.abortTransaction();
          return;  // Exit processing if a failure occurs
        }
      }

      // Commit the transaction if all messages are processed successfully
      await session.commitTransaction();
      if (pendingMessages.length > 0 ){
        this.logger.log('All messages processed successfully, transaction committed.');

      }

    } catch (error) {
      this.logger.error(`Failed to process outbox messages. Error: ${error instanceof Error ? error.stack : 'Unknown error occurred.'}`);
      // Abort the transaction in case of any general error
      await session.abortTransaction();
    } finally {
      // End the session
      session.endSession();
    }
  }
}
