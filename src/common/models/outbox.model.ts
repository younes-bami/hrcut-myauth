// src/common/outbox/outbox.model.ts
import { model, Model } from 'mongoose';
import { OutboxDocument,OutboxSchema } from '../../outboxProcessor/schemas/outbox.schema';

export const OutboxModel: Model<OutboxDocument> = model<OutboxDocument>('Outbox', OutboxSchema);
