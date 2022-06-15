import { IUser } from '@/interfaces/IUser';
import mongoose from 'mongoose';

const User = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Please enter a full name'],
      index: true,
    },

    email: {
      type: String,
      lowercase: true,
      unique: true,
      index: true,
    },

    password: String,
    username: String,

    salt: String,

    role: {
      type: String,
      default: 'user',
    },

    street: String,
    city: String,
    street_line_2: String,
    zip: String,
    state: String,

    NewPassword:String,
    confirmNewPassword:String,

  },
  { timestamps: true },
);

export default mongoose.model<IUser & mongoose.Document>('User', User);
