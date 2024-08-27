import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { ScheduleModule } from '@nestjs/schedule';
import { OutboxService } from './outbox.service';
import { OutboxProcessorService } from './outbox-processor.service';
import { OutboxSchema } from './schemas/outbox.schema';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: 'Outbox', schema: OutboxSchema }]),
    ScheduleModule.forRoot(),
  ],
  providers: [OutboxService, OutboxProcessorService],
  exports: [OutboxService],
})
export class OutboxModule {}
