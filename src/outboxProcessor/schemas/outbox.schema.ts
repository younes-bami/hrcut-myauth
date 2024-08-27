import { Schema, Document } from 'mongoose';

export interface OutboxDocument extends Document {
  eventType: string;
  payload: any;
  status: 'PENDING' | 'PROCESSING' | 'PROCESSED' | 'FAILED';
  createdAt: Date;
  updatedAt: Date;
}

export const OutboxSchema = new Schema<OutboxDocument>({
    eventType: { type: String, required: true },
    payload: { type: Object, required: true },
    status: {
      type: String,
      enum: ['PENDING', 'PROCESSING', 'PROCESSED', 'FAILED'], // Ensure "PROCESSING" is included
      default: 'PENDING',
    },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
  });
  