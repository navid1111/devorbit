import mongoose, { Document, Schema, Types } from 'mongoose';

export type BookingStatus = 
  | 'created' 
  | 'advance_payment_completed' 
  | 'completed' 
  | 'cancelled';

export type PaymentMethod = 'stripe' | 'cash';

export interface IBooking extends Document {
  userId: Types.ObjectId;
  turf: Types.ObjectId;
  timeSlots: Types.ObjectId[];
  totalAmount: number;
  advanceAmount: number;
  finalAmount: number;
  status: BookingStatus;
  advancePaymentTransactionId: string;
  finalPaymentTransactionId?: string;
  finalPaymentMethod?: PaymentMethod;
  isPaid: boolean;
  isReminderSent: boolean; 
  createdAt: Date;
  updatedAt: Date;
}

const BookingSchema: Schema = new Schema(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    turf: {
      type: Schema.Types.ObjectId,
      ref: 'Turf',
      required: true,
      index: true,
    },
    timeSlots: [{
      type: Schema.Types.ObjectId,
      ref: 'TimeSlot',
      required: true,
    }],
    totalAmount: {
      type: Number,
      required: true,
      min: 0,
      get: (v: number) => parseFloat(v.toFixed(2)),
      set: (v: number) => parseFloat(v.toFixed(2)),
    },
    advanceAmount: {
      type: Number,
      required: true,
      min: 0,
      get: (v: number) => parseFloat(v.toFixed(2)),
      set: (v: number) => parseFloat(v.toFixed(2)),
    },
    finalAmount: {
      type: Number,
      required: true,
      min: 0,
      get: (v: number) => parseFloat(v.toFixed(2)),
      set: (v: number) => parseFloat(v.toFixed(2)),
    },
    status: {
      type: String,
      enum: ['created', 'advance_payment_completed', 'completed', 'rejected'],
      default: 'created',
      index: true,
    },
    advancePaymentTransactionId: {
      type: String,
      required: true,
    },
    finalPaymentTransactionId: {
      type: String,
    },
    finalPaymentMethod: {
      type: String,
      enum: ['stripe', 'cash'],
    },
    isPaid: {
      type: Boolean,
      default: false,
      index: true,
    },
    isReminderSent: {  
      type: Boolean,
      default: false,
      index: true,
    }
  },
  { timestamps: true },
);

// Index for common queries
BookingSchema.index({ userId: 1, status: 1 });
BookingSchema.index({ turf: 1, status: 1 });
BookingSchema.index({ createdAt: -1 });

export const Booking = mongoose.model<IBooking>('Booking', BookingSchema);