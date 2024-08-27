import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { OutboxService } from './outbox.service';

@Injectable()
export class OutboxProcessorService implements OnModuleInit {
  private readonly logger = new Logger(OutboxProcessorService.name);

  constructor(private readonly outboxService: OutboxService) {}

  onModuleInit() {
    this.logger.log('OutboxProcessorService initialized');
  }

  @Cron(CronExpression.EVERY_5_SECONDS)  // Adjust the frequency as needed
  async handleOutboxProcessing() {
    this.logger.log('Cron job triggered');
    await this.outboxService.processOutboxMessages();
    this.logger.log('Processing complete');
  }
}
