import * as dotenv from 'dotenv';

dotenv.config();

if (!process.env.RABBITMQ_URL) {
  throw new Error('RABBITMQ_URL is not defined');
}

if (!process.env.RABBITMQ_QUEUE) {
  throw new Error('QUEUE_NAME is not defined');
}

export const rabbitmqConfig = {
  url: process.env.RABBITMQ_URL,
  queue: process.env.RABBITMQ_QUEUE,
};
