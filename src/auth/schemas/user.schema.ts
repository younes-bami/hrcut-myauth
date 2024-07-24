import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';

@Schema()
export class User {
  @Prop({ required: true, unique: true })
  username!: string;

  @Prop({ required: true })
  password!: string;

  @Prop({ required: true, unique: true })
  email!: string;

  @Prop({ required: true }) // Ajout du numéro de téléphone
  phoneNumber!: string;

  @Prop()
  firstName?: string;

  @Prop()
  lastName?: string;

  @Prop({ default: Date.now })
  createdAt!: Date;

  @Prop({ type: [String], default: ['Customer'] }) // Définir les rôles par défaut
  roles!: string[];
}

export type UserDocument = User & Document & { _id: Types.ObjectId }; // Assurez-vous que _id est de type Types.ObjectId
export const UserSchema = SchemaFactory.createForClass(User);
