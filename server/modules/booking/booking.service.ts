import mongoose, { Types } from 'mongoose';
import { Booking, BookingStatus, IBooking, PaymentMethod } from './booking.model';
import { TimeSlot } from '../timeslot/timeslot.model';
import { Turf } from '../turf/turf.model';
import ErrorResponse from '../../utils/errorResponse';
import { validateId } from '../../utils/validation';
import { sendEmail } from '../../utils/email';
import User from '../user/user.model';
import { z } from 'zod';

export interface CreateBookingDto {
  turfId: string;
  timeSlotIds: string[];
  advancePaymentTransactionId: string;
}

export interface CompleteBookingDto {
  finalPaymentMethod: PaymentMethod;
  finalPaymentTransactionId?: string;
}

export interface BookingFilters {
  userId?: string;
  turfId?: string;
  status?: BookingStatus | BookingStatus[];
  fromDate?: Date;
  toDate?: Date;
  isPaid?: boolean;
  sortBy?: 'createdAt' | 'updatedAt' | 'totalAmount';
  sortOrder?: 'asc' | 'desc';
}

export interface PaginationOptions {
  page: number;
  limit: number;
}

export interface BookingsResult {
  total: number;
  page: number;
  pages: number;
  bookings: IBooking[];
}

export default class BookingService {
  private readonly ADVANCE_PAYMENT_PERCENTAGE = 0.65; // 65% advance payment
  private readonly ALLOWED_STATUSES = ['pending', 'advance_payment_completed', 'completed'];
  private readonly ALLOWED_SORT_FIELDS = ['createdAt', 'updatedAt', 'totalAmount'];

  /**
   * Create a new booking with advance payment
   */
  async createBooking(userId: string, bookingData: CreateBookingDto): Promise<IBooking> {
    // Start a transaction
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Validate IDs
      const validUserId = validateId(userId);
      const validTurfId = validateId(bookingData.turfId);
      const validTimeSlotIds = bookingData.timeSlotIds.map(id => validateId(id));

      // 1. Check if timeSlots are available
      const timeSlots = await TimeSlot.find({
        _id: { $in: validTimeSlotIds },
        is_available: true
      }).session(session);

      if (timeSlots.length !== validTimeSlotIds.length) {
        throw new ErrorResponse('One or more time slots are no longer available', 400);
      }

      // 2. Validate if user is verified
      const user = await User.findById(validUserId).session(session);
      if (!user) {
        throw new ErrorResponse('User not found', 404);
      }
      if (!user.isVerified) {
        throw new ErrorResponse('User is not verified', 403);
      }

      // 3. Validate if all slots belong to the same turf
      const turfIds = timeSlots.map(slot => slot.turf.toString());
      if (new Set(turfIds).size !== 1 || turfIds[0] !== validTurfId) {
        throw new ErrorResponse('All time slots must belong to the same turf', 400);
      }

      // 4. Get turf for base price
      const turf = await Turf.findById(validTurfId).session(session);
      if (!turf) {
        throw new ErrorResponse('Turf not found', 404);
      }

      // 5. Calculate total, advance, and final amounts
      const basePrice = turf.basePrice || 0;
      const totalAmount = basePrice * timeSlots.length;
      const advanceAmount = totalAmount * this.ADVANCE_PAYMENT_PERCENTAGE;
      const finalAmount = totalAmount - advanceAmount;

      // 6. Create booking
      const booking = await Booking.create([{
        userId: new Types.ObjectId(validUserId),
        turf: new Types.ObjectId(validTurfId),
        timeSlots: timeSlots.map(slot => slot._id),
        totalAmount,
        advanceAmount,
        finalAmount,
        status: 'advance_payment_completed',
        advancePaymentTransactionId: bookingData.advancePaymentTransactionId,
        isPaid: false
      }], { session });

      // 7. Update time slots to not available and set booking reference
      await TimeSlot.updateMany(
        { _id: { $in: validTimeSlotIds } },
        {
          is_available: false,
          booking: booking[0]._id // Set the booking reference
        },
        { session }
      );

      // Commit transaction
      await session.commitTransaction();

      // send email
      await this.sendBookingConfirmationEmail(booking[0]);

      return booking[0];
    } catch (error) {
      // Abort transaction on error
      await session.abortTransaction();

      if (error instanceof z.ZodError) {
        throw new ErrorResponse('Invalid ID format', 400);
      }

      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
 * Complete a booking with Stripe payment
 */
  async completeBookingWithStripe(bookingId: string, transactionId: string): Promise<IBooking> {
    try {
      const validBookingId = validateId(bookingId);

      const booking = await Booking.findById(validBookingId);
      if (!booking) {
        throw new ErrorResponse('Booking not found', 404);
      }

      if (booking.status !== 'advance_payment_completed') {
        throw new ErrorResponse('This booking cannot be completed due to its current status', 400);
      }

      booking.finalPaymentMethod = 'stripe';
      booking.finalPaymentTransactionId = transactionId;
      booking.status = 'completed';
      booking.isPaid = true;
      

      await booking.save();

      // send email
      await this.sendBookingCompletionEmail(booking);

      return booking;
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new ErrorResponse('Invalid booking ID format', 400);
      }

      throw error;
    }
  }

  /**
   * Complete a booking with cash payment
   */
  async completeBookingWithCash(bookingId: string): Promise<IBooking> {
    try {
      const validBookingId = validateId(bookingId);

      const booking = await Booking.findById(validBookingId);
      if (!booking) {
        throw new ErrorResponse('Booking not found', 404);
      }

      if (booking.status !== 'advance_payment_completed') {
        throw new ErrorResponse('This booking cannot be completed due to its current status', 400);
      }

      booking.finalPaymentMethod = 'cash';
      booking.status = 'completed';
      booking.isPaid = true;
      

      await booking.save();

      // send email
      await this.sendBookingCompletionEmail(booking);

      return booking;
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new ErrorResponse('Invalid booking ID format', 400);
      }

      throw error;
    }
  }


  /**
   * Get booking by ID with relations
   */
  async getBookingById(bookingId: string): Promise<IBooking> {
    try {
      const validBookingId = validateId(bookingId);

      const booking = await Booking.findById(validBookingId)
        .populate('userId', 'first_name last_name email phone_number')
        .populate('turf')
        .populate('timeSlots');

      if (!booking) {
        throw new ErrorResponse('Booking not found', 404);
      }

      return booking;
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new ErrorResponse('Invalid booking ID format', 400);
      }

      throw error;
    }
  }

  /**
  * Sanitize and validate ObjectId
  * @private
  */
  private sanitizeObjectId(id: string, fieldName: string): Types.ObjectId {
    try {
      const validId = validateId(id);
      return new Types.ObjectId(validId);
    } catch (error) {
      throw new ErrorResponse(`Invalid ${fieldName} format`, 400);
    }
  }

  /**
   * Sanitize status filter
   * @private
   */
  private sanitizeStatusFilter(status: BookingStatus | BookingStatus[]): BookingStatus | { $in: BookingStatus[] } {
    if (Array.isArray(status)) {
      const validStatuses = status.filter(s =>
        this.ALLOWED_STATUSES.includes(s)
      );
      return validStatuses.length > 0 ? { $in: validStatuses } : { $in: [] };
    } else if (this.ALLOWED_STATUSES.includes(status)) {
      return status;
    }
    return { $in: [] }; // Return empty filter if invalid status
  }

  /**
   * Sanitize date filter
   * @private
   */
  private sanitizeDateFilter(fromDate?: Date, toDate?: Date): { $gte?: Date, $lte?: Date } | null {
    const dateFilter: { $gte?: Date, $lte?: Date } = {};
    let hasValidDate = false;

    if (fromDate) {
      const parsedFromDate = new Date(fromDate);
      if (!isNaN(parsedFromDate.getTime())) {
        dateFilter.$gte = parsedFromDate;
        hasValidDate = true;
      }
    }

    if (toDate) {
      const parsedToDate = new Date(toDate);
      if (!isNaN(parsedToDate.getTime())) {
        dateFilter.$lte = parsedToDate;
        hasValidDate = true;
      }
    }

    return hasValidDate ? dateFilter : null;
  }

  /**
   * Sanitize sort options
   * @private
   */
  private sanitizeSortOptions(sortBy?: string, sortOrder?: string): Record<string, 1 | -1> {
    const sortOptions: Record<string, 1 | -1> = {};
    const validSortBy = this.ALLOWED_SORT_FIELDS.includes(sortBy as any)
      ? sortBy
      : 'createdAt';

    const validSortOrder = sortOrder === 'asc' ? 1 : -1;
    sortOptions[validSortBy as string] = validSortOrder;

    return sortOptions;
  }

  /**
   * Build a sanitized query from filters
   * @private
   */
  private buildSanitizedQuery(filters: BookingFilters, baseQuery: Record<string, any> = {}): Record<string, any> {
    const query = { ...baseQuery };

    // userId filter (if not already in base query)
    if (filters.userId && !query.userId) {
      query.userId = this.sanitizeObjectId(filters.userId, 'user ID');
    }

    // turfId filter (if not already in base query)
    if (filters.turfId && !query.turf) {
      query.turf = this.sanitizeObjectId(filters.turfId, 'turf ID');
    }

    // Status filter
    if (filters.status) {
      query.status = this.sanitizeStatusFilter(filters.status);
    }

    // Date filters
    if (filters.fromDate || filters.toDate) {
      const dateFilter = this.sanitizeDateFilter(filters.fromDate, filters.toDate);
      if (dateFilter) {
        query.createdAt = dateFilter;
      }
    }

    // isPaid filter
    if (filters.isPaid !== undefined) {
      query.isPaid = Boolean(filters.isPaid);
    }

    return query;
  }

  /**
   * Execute paginated query with sanitized parameters
   * @private
   */
  private async executePaginatedQuery(
    query: Record<string, any>,
    sortOptions: Record<string, 1 | -1>,
    pagination: PaginationOptions,
    populate: Array<{ path: string, select?: string }> = []
  ): Promise<BookingsResult> {
    // Sanitize pagination
    const page = Math.max(1, pagination.page || 1);
    const limit = Math.min(50, Math.max(1, pagination.limit || 10));
    const skip = (page - 1) * limit;

    // Count total before pagination
    const total = await Booking.countDocuments(query);
    const pages = Math.ceil(total / limit);

    // Build query
    let bookingsQuery = Booking.find(query)
      .sort(sortOptions)
      .skip(skip)
      .limit(limit);

    // Apply population
    for (const pop of populate) {
      bookingsQuery = bookingsQuery.populate(pop.path, pop.select);
    }

    // Execute query
    const bookings = await bookingsQuery;

    return {
      total,
      page,
      pages,
      bookings,
    };
  }

  /**
   * Get all bookings with filters and pagination
   */
  async getBookings(
    filters: BookingFilters = {},
    pagination: PaginationOptions = { page: 1, limit: 10 }
  ): Promise<BookingsResult> {
    try {
      // Build sanitized query
      const query = this.buildSanitizedQuery(filters);

      // Build sanitized sort options
      const sortOptions = this.sanitizeSortOptions(filters.sortBy, filters.sortOrder);

      // Define populate options
      const populate = [
        { path: 'userId', select: 'first_name last_name email' },
        { path: 'turf', select: 'name location' },
        { path: 'timeSlots', select: 'start_time end_time' }
      ];

      // Execute query
      return await this.executePaginatedQuery(query, sortOptions, pagination, populate);
    } catch (error) {
      if (error instanceof ErrorResponse) {
        throw error;
      }
      throw new ErrorResponse('Error fetching bookings', 500);
    }
  }

  /**
   * Get user bookings with filters, sorting and pagination
   */
  async getUserBookings(
    userId: string,
    filters: BookingFilters = {},
    pagination: PaginationOptions = { page: 1, limit: 10 }
  ): Promise<BookingsResult> {
    try {
      // Validate user ID
      const validUserId = this.sanitizeObjectId(userId, 'user ID');

      // Build sanitized query with base query containing userId
      const query = this.buildSanitizedQuery(filters, { userId: validUserId });

      // Build sanitized sort options
      const sortOptions = this.sanitizeSortOptions(filters.sortBy, filters.sortOrder);

      // Define populate options
      const populate = [
        { path: 'turf', select: 'name basePrice' },
        { path: 'timeSlots', select: 'start_time end_time' }
      ];

      // Execute query
      return await this.executePaginatedQuery(query, sortOptions, pagination, populate);
    } catch (error) {
      if (error instanceof ErrorResponse) {
        throw error;
      }
      if (error instanceof z.ZodError) {
        throw new ErrorResponse('Invalid user ID format', 400);
      }
      throw error;
    }
  }

  /**
   * Get bookings for a specific turf with filters, sorting and pagination
   */
  async getTurfBookings(
    turfId: string,
    filters: BookingFilters = {},
    pagination: PaginationOptions = { page: 1, limit: 10 }
  ): Promise<BookingsResult> {
    try {
      // Validate turf ID
      const validTurfId = this.sanitizeObjectId(turfId, 'turf ID');

      // Build sanitized query with base query containing turfId
      const query = this.buildSanitizedQuery(filters, { turf: validTurfId });

      // Build sanitized sort options
      const sortOptions = this.sanitizeSortOptions(filters.sortBy, filters.sortOrder);

      // Define populate options
      const populate = [
        { path: 'userId', select: 'first_name last_name email' },
        { path: 'timeSlots', select: 'start_time end_time' }
      ];

      // Execute query
      return await this.executePaginatedQuery(query, sortOptions, pagination, populate);
    } catch (error) {
      if (error instanceof ErrorResponse) {
        throw error;
      }
      if (error instanceof z.ZodError) {
        throw new ErrorResponse('Invalid turf ID format', 400);
      }
      throw error;
    }
  }


  /**
 * Get monthly earnings for a turf for the current year
 * Considers both fully completed bookings and partially paid bookings
 */
  async getTurfMonthlyEarnings(turfId: string): Promise<{ month: number; earnings: number }[]> {
    try {
      const validTurfId = validateId(turfId);

      // Get current year
      const currentYear = new Date().getFullYear();
      const startDate = new Date(currentYear, 0, 1); // January 1st of current year
      const endDate = new Date(currentYear, 11, 31, 23, 59, 59); // December 31st of current year

      // Aggregate monthly earnings for all bookings in the current year
      const monthlyEarnings = await Booking.aggregate([
        {
          $match: {
            turf: new Types.ObjectId(validTurfId),
            status: { $in: ['advance_payment_completed', 'completed'] },
            createdAt: { $gte: startDate, $lte: endDate }
          }
        },
        {
          $addFields: {
            // For completed bookings, use totalAmount; for advance_payment_completed, use only advanceAmount
            actualEarnings: {
              $cond: [
                { $eq: ["$status", "completed"] },
                "$totalAmount",
                "$advanceAmount"
              ]
            }
          }
        },
        {
          $group: {
            _id: { $month: '$createdAt' },
            earnings: { $sum: '$actualEarnings' }
          }
        },
        {
          $project: {
            _id: 0,
            month: '$_id',
            earnings: { $round: ['$earnings', 2] }
          }
        },
        {
          $sort: { month: 1 }
        }
      ]);

      // Create an array for all 12 months with 0 earnings as default
      const result = Array.from({ length: 12 }, (_, i) => ({
        month: i + 1,
        earnings: 0
      }));

      // Update earnings for months that have data
      monthlyEarnings.forEach(item => {
        result[item.month - 1].earnings = item.earnings;
      });

      return result;
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new ErrorResponse('Invalid turf ID format', 400);
      }
      throw error;
    }
  }

  /**
 * Get current month's earnings for a turf
 * Considers both fully completed bookings and partially paid bookings
 */
  async getTurfCurrentMonthEarnings(turfId: string): Promise<{ earnings: number }> {
    try {
      const validTurfId = validateId(turfId);

      // Get current month's start and end dates
      const now = new Date();
      const startDate = new Date(now.getFullYear(), now.getMonth(), 1);
      const endDate = new Date(now.getFullYear(), now.getMonth() + 1, 0, 23, 59, 59);

      // Aggregate earnings for bookings in current month
      const result = await Booking.aggregate([
        {
          $match: {
            turf: new Types.ObjectId(validTurfId),
            status: { $in: ['advance_payment_completed', 'completed'] },
            createdAt: { $gte: startDate, $lte: endDate }
          }
        },
        {
          $addFields: {
            // For completed bookings, use totalAmount; for advance_payment_completed, use only advanceAmount
            actualEarnings: {
              $cond: [
                { $eq: ["$status", "completed"] },
                "$totalAmount",
                "$advanceAmount"
              ]
            }
          }
        },
        {
          $group: {
            _id: null,
            earnings: { $sum: '$actualEarnings' }
          }
        },
        {
          $project: {
            _id: 0,
            earnings: { $round: ['$earnings', 2] }
          }
        }
      ]);

      return result.length > 0 ? result[0] : { earnings: 0 };
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new ErrorResponse('Invalid turf ID format', 400);
      }
      throw error;
    }
  }

  /**
 * Get current month's earnings for an organization (all turfs combined)
 * Considers both fully completed bookings and partially paid bookings
 */
  async getOrganizationCurrentMonthEarnings(organizationId: string): Promise<{ earnings: number }> {
    try {
      const validOrgId = validateId(organizationId);

      // Get current month's start and end dates
      const now = new Date();
      const startDate = new Date(now.getFullYear(), now.getMonth(), 1);
      const endDate = new Date(now.getFullYear(), now.getMonth() + 1, 0, 23, 59, 59);

      // First get all turf IDs belonging to this organization
      const turfs = await Turf.find({ organization: validOrgId }, '_id');
      const turfIds = turfs.map(turf => turf._id);

      if (turfIds.length === 0) {
        return { earnings: 0 };
      }

      // Aggregate earnings for all bookings across all turfs in current month
      const result = await Booking.aggregate([
        {
          $match: {
            turf: { $in: turfIds },
            status: { $in: ['advance_payment_completed', 'completed'] },
            createdAt: { $gte: startDate, $lte: endDate }
          }
        },
        {
          $addFields: {
            // For completed bookings, use totalAmount; for advance_payment_completed, use only advanceAmount
            actualEarnings: {
              $cond: [
                { $eq: ["$status", "completed"] },
                "$totalAmount",
                "$advanceAmount"
              ]
            }
          }
        },
        {
          $group: {
            _id: null,
            earnings: { $sum: '$actualEarnings' }
          }
        },
        {
          $project: {
            _id: 0,
            earnings: { $round: ['$earnings', 2] }
          }
        }
      ]);

      return result.length > 0 ? result[0] : { earnings: 0 };
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new ErrorResponse('Invalid organization ID format', 400);
      }
      throw error;
    }
  }

  private async sendBookingConfirmationEmail(booking: IBooking) {
    try {
      const user = await User.findById(booking.userId);
      if (!user || !user.email) return;

      // Get turf details
      const turf = await Turf.findById(booking.turf);
      const turfName = turf ? turf.name : 'Our facility';

      // Get timeslot details
      const timeSlots = await TimeSlot.find({
        _id: { $in: booking.timeSlots }
      }).sort({ start_time: 1 });

      // Format time slots nicely for display
      const formattedTimeSlots = timeSlots.map(slot => {
        const startTime = new Date(slot.start_time).toLocaleTimeString('en-US', {
          hour: '2-digit',
          minute: '2-digit'
        });
        const endTime = new Date(slot.end_time).toLocaleTimeString('en-US', {
          hour: '2-digit',
          minute: '2-digit'
        });
        const date = new Date(slot.start_time).toLocaleDateString('en-US', {
          weekday: 'long',
          year: 'numeric',
          month: 'long',
          day: 'numeric'
        });
        return { date, startTime, endTime };
      });

      // Group slots by date for cleaner email formatting
      const slotsByDate = formattedTimeSlots.reduce((acc: Record<string, { startTime: string, endTime: string }[]>, slot) => {
        if (!acc[slot.date]) {
          acc[slot.date] = [];
        }
        acc[slot.date].push({ startTime: slot.startTime, endTime: slot.endTime });
        return acc;
      }, {});

      // Format currency
      const formatCurrency = (amount: number) => {
        return new Intl.NumberFormat('en-US', {
          style: 'currency',
          currency: 'USD'
        }).format(amount);
      };

      const subject = `Booking Confirmation - ${turfName}`;
      const text = `Dear ${user.first_name},\n\nYour booking has been confirmed.\n\nBooking ID: ${booking._id}\nTotal Amount: ${formatCurrency(booking.totalAmount)}\nAdvance Paid: ${formatCurrency(booking.advanceAmount)}\nBalance Due: ${formatCurrency(booking.finalAmount)}\n\nThank you for using our service.`;

      // Create HTML content for the email
      const htmlContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eaeaea; border-radius: 5px; background-color: #f9f9f9;">
        <h2 style="color: #4a9d61; text-align: center; margin-bottom: 20px;">Booking Confirmation</h2>
        
        <div style="background-color: #ffffff; border: 1px solid #eaeaea; border-radius: 3px; padding: 15px; margin-bottom: 20px;">
          <h3 style="color: #333; margin-top: 0;">Dear ${user.first_name},</h3>
          <p style="font-size: 16px; line-height: 1.5;">Your booking at <strong>${turfName}</strong> has been confirmed! We've received your advance payment of <strong>${formatCurrency(booking.advanceAmount)}</strong>.</p>
        </div>
        
        <div style="background-color: #eafbf0; border-left: 4px solid #4a9d61; padding: 15px; margin-bottom: 20px;">
          <h3 style="color: #333; margin-top: 0;">Booking Details</h3>
          <table style="width: 100%; border-collapse: collapse;">
            <tr>
              <td style="padding: 8px 0; border-bottom: 1px solid #eee;">Booking ID</td>
              <td style="padding: 8px 0; border-bottom: 1px solid #eee; text-align: right;"><strong>${booking._id}</strong></td>
            </tr>
            <tr>
              <td style="padding: 8px 0; border-bottom: 1px solid #eee;">Status</td>
              <td style="padding: 8px 0; border-bottom: 1px solid #eee; text-align: right;"><span style="background-color: #4a9d61; color: white; padding: 3px 8px; border-radius: 12px; font-size: 12px;">CONFIRMED</span></td>
            </tr>
            <tr>
              <td style="padding: 8px 0; border-bottom: 1px solid #eee;">Total Amount</td>
              <td style="padding: 8px 0; border-bottom: 1px solid #eee; text-align: right;">${formatCurrency(booking.totalAmount)}</td>
            </tr>
            <tr>
              <td style="padding: 8px 0; border-bottom: 1px solid #eee;">Advance Paid</td>
              <td style="padding: 8px 0; border-bottom: 1px solid #eee; text-align: right;">${formatCurrency(booking.advanceAmount)}</td>
            </tr>
            <tr>
              <td style="padding: 8px 0;">Balance Due</td>
              <td style="padding: 8px 0; text-align: right; font-weight: bold;">${formatCurrency(booking.finalAmount)}</td>
            </tr>
          </table>
        </div>
        
        <div style="margin-bottom: 20px;">
          <h3 style="color: #333;">Reserved Time Slots</h3>
          ${Object.entries(slotsByDate).map(([date, slots]) => `
          <div style="margin-bottom: 15px;">
            <h4 style="margin-bottom: 8px; color: #4a9d61;">${date}</h4>
            <ul style="list-style-type: none; padding-left: 0; margin: 0;">
              ${slots.map(slot => `
              <li style="padding: 8px; background-color: #f0f0f0; margin-bottom: 5px; border-radius: 3px;">
                ${slot.startTime} - ${slot.endTime}
              </li>
              `).join('')}
            </ul>
          </div>
          `).join('')}
        </div>
        
        <p style="font-size: 14px; color: #666; margin-top: 30px; border-top: 1px solid #eee; padding-top: 20px;">
          Please arrive 15 minutes before your scheduled time. The balance payment of <strong>${formatCurrency(booking.finalAmount)}</strong> is due at the venue before your session.
        </p>
      </div>
      `;

      await sendEmail(
        user.email,
        subject,
        text,
        htmlContent
      );
    } catch (error) {
      console.error('Error sending booking confirmation email:', error);
    }
  }

  private async sendBookingCompletionEmail(booking: IBooking) {
    try {
      const user = await User.findById(booking.userId);
      if (!user || !user.email) return;

      // Get turf details
      const turf = await Turf.findById(booking.turf);
      const turfName = turf ? turf.name : 'Our facility';

      // Format currency for display
      const formatCurrency = (amount: number) => {
        return new Intl.NumberFormat('en-US', {
          style: 'currency',
          currency: 'USD'
        }).format(amount);
      };

      const subject = 'Booking Completed - TurfMania';
      const text = `Dear ${user.first_name},\n\nYour booking has been successfully completed.\n\nBooking ID: ${booking._id}\nFinal Amount Paid: ${formatCurrency(booking.finalAmount)}\nTotal Amount: ${formatCurrency(booking.totalAmount)}\n\nThank you for using our service.`;

      const paymentMethod = booking.finalPaymentMethod === 'stripe' ? 'card' : booking.finalPaymentMethod;

      // Create HTML content for the email
      const htmlContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eaeaea; border-radius: 5px; background-color: #f9f9f9;">
        <h2 style="color: #4a9d61; text-align: center; margin-bottom: 20px;">Payment Completed</h2>
        
        <div style="background-color: #ffffff; border: 1px solid #eaeaea; border-radius: 3px; padding: 15px; margin-bottom: 20px;">
          <h3 style="color: #333; margin-top: 0;">Dear ${user.first_name},</h3>
          <p style="font-size: 16px; line-height: 1.5;">Thank you for your payment! Your booking at <strong>${turfName}</strong> has been completed successfully.</p>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
          <div style="display: inline-block; background-color: #eafbf0; border-radius: 50%; width: 80px; height: 80px; line-height: 80px; text-align: center;">
            <svg width="40" height="40" viewBox="0 0 24 24" style="display: inline-block; vertical-align: middle;">
              <path fill="#4a9d61" d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"></path>
            </svg>
          </div>
          <p style="font-size: 18px; color: #4a9d61; font-weight: bold; margin-top: 15px;">Payment Successful</p>
        </div>
        
        <div style="background-color: #eafbf0; border-left: 4px solid #4a9d61; padding: 15px; margin-bottom: 20px;">
          <h3 style="color: #333; margin-top: 0;">Payment Details</h3>
          <table style="width: 100%; border-collapse: collapse;">
            <tr>
              <td style="padding: 8px 0; border-bottom: 1px solid #eee;">Booking ID</td>
              <td style="padding: 8px 0; border-bottom: 1px solid #eee; text-align: right;"><strong>${booking._id}</strong></td>
            </tr>
            <tr>
              <td style="padding: 8px 0; border-bottom: 1px solid #eee;">Payment Method</td>
              <td style="padding: 8px 0; border-bottom: 1px solid #eee; text-align: right; text-transform: capitalize;">${paymentMethod}</td>
            </tr>
            <tr>
              <td style="padding: 8px 0; border-bottom: 1px solid #eee;">Final Payment</td>
              <td style="padding: 8px 0; border-bottom: 1px solid #eee; text-align: right;">${formatCurrency(booking.finalAmount)}</td>
            </tr>
            <tr>
              <td style="padding: 8px 0; border-bottom: 1px solid #eee;">Advance Paid</td>
              <td style="padding: 8px 0; border-bottom: 1px solid #eee; text-align: right;">${formatCurrency(booking.advanceAmount)}</td>
            </tr>
            <tr>
              <td style="padding: 8px 0;">Total Amount</td>
              <td style="padding: 8px 0; text-align: right; font-weight: bold;">${formatCurrency(booking.totalAmount)}</td>
            </tr>
          </table>
        </div>
      </div>
      `;

      await sendEmail(
        user.email,
        subject,
        text,
        htmlContent
      );
    } catch (error) {
      console.error('Error sending booking completion email:', error);
    }
  }

  private async sendBookingReminderEmail(booking: IBooking): Promise<void> {
    try {
      const user = await User.findById(booking.userId);
      if (!user || !user.email) return;

      // Get turf and timeslot details for reminder
      const turf = await Turf.findById(booking.turf);
      const turfName = turf ? turf.name : 'our facility';

      const timeSlots = await TimeSlot.find({
        _id: { $in: booking.timeSlots }
      }).sort({ start_time: 1 });

      // Get the first timeslot for reminder
      const firstSlot = timeSlots.length > 0 ? timeSlots[0] : null;
      let slotTime = 'your scheduled time';

      if (firstSlot) {
        const startTime = new Date(firstSlot.start_time).toLocaleTimeString('en-US', {
          hour: '2-digit',
          minute: '2-digit'
        });
        const date = new Date(firstSlot.start_time).toLocaleDateString('en-US', {
          weekday: 'long',
          year: 'numeric',
          month: 'long',
          day: 'numeric'
        });
        slotTime = `${date} at ${startTime}`;
      }

      const subject = '🏆 Your Booking Starts Soon - TurfMania';
      const text = `Dear ${user.first_name},\n\nYour booking at ${turfName} is starting soon (in 30 minutes).\n\nBooking ID: ${booking._id}\n\nPlease arrive on time.\n\nThank you for using TurfMania.`;

      // Create HTML content for the reminder email
      const htmlContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eaeaea; border-radius: 5px; background-color: #f9f9f9;">
        <h2 style="color: #4a9d61; text-align: center; margin-bottom: 20px;">Your Session Starts Soon!</h2>
        
        <div style="background-color: #ffffff; border: 1px solid #eaeaea; border-radius: 3px; padding: 15px; margin-bottom: 20px;">
          <h3 style="color: #333; margin-top: 0;">Dear ${user.first_name},</h3>
          <p style="font-size: 16px; line-height: 1.5;">This is a friendly reminder that your booking at <strong>${turfName}</strong> is starting soon.</p>
        </div>
        
        <div style="background-color: #fffbea; border-left: 4px solid #f9a825; padding: 15px; margin-bottom: 20px;">
          <h3 style="color: #333; margin-top: 0; margin-bottom: 10px;">⏰ Starting in 30 minutes</h3>
          <p style="font-size: 15px; margin: 0;">Your session is scheduled for <strong>${slotTime}</strong></p>
        </div>
        
        <div style="background-color: #eafbf0; border-left: 4px solid #4a9d61; padding: 15px; margin-bottom: 20px;">
          <h3 style="color: #333; margin-top: 0; margin-bottom: 10px;">Booking Details</h3>
          <p style="margin: 0;"><strong>Booking ID:</strong> ${booking._id}</p>
          ${booking.status !== 'completed' ? `
          <p style="margin-top: 10px; color: #d32f2f;"><strong>Reminder:</strong> Please remember to bring your balance payment of ${new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(booking.finalAmount)}</p>
          ` : ''}
        </div>
        
        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee;">
          <p style="font-size: 14px; color: #666;">Recommended:</p>
          <ul style="font-size: 14px; color: #666;">
            <li>Arrive 15 minutes before your scheduled time</li>
            <li>Bring appropriate footwear for the turf</li>
            <li>Don't forget to bring water</li>
          </ul>
        </div>
      </div>
      `;

      await sendEmail(
        user.email,
        subject,
        text,
        htmlContent
      );
    } catch (error) {
      console.error('Error sending booking reminder email:', error);
      throw error;
    }
  }

  public async sendBookingReminders(): Promise<number> {
    try {
      // Get current time and 30 minutes from now
      const now = new Date();
      const reminderTime = new Date(now.getTime() + 30 * 60 * 1000); // 30 minutes from now

      // Find bookings with advance payment completed where first timeslot starts soon
      const bookings = await Booking.aggregate([
        {
          $match: {
            status: { $in: ['advance_payment_completed', 'completed'] },
            isReminderSent: { $ne: true } // Only if reminder hasn't been sent
          }
        },
        {
          $lookup: {
            from: 'timeslots',
            localField: 'timeSlots',
            foreignField: '_id',
            as: 'timeslotDetails'
          }
        },
        {
          $addFields: {
            firstTimeslot: { $min: '$timeslotDetails.start_time' }
          }
        },
        {
          $match: {
            'firstTimeslot': {
              $gte: now,
              $lte: reminderTime
            }
          }
        }
      ]);

      // Send reminders and mark as sent
      let remindersSent = 0;
      for (const booking of bookings) {
        try {
          await this.sendBookingReminderEmail(booking);
          await Booking.updateOne(
            { _id: booking._id },
            { $set: { isReminderSent: true } }
          );
          remindersSent++;
        } catch (error) {
          console.error(`Failed to send reminder for booking ${booking._id}:`, error);
        }
      }

      return remindersSent;
    } catch (error) {
      console.error('Error sending booking reminders:', error);
      return 0;
    }
  }

  /**
   * Start periodic reminder service
   */
  public startPeriodicReminders(intervalMinutes: number = 5): void {
    const intervalMs = intervalMinutes * 60 * 1000;

    setInterval(async () => {
      try {
        const count = await this.sendBookingReminders();
        if (count > 0) {
          console.log(`Sent ${count} booking reminders`);
        }
      } catch (error) {
        console.error('Error sending booking reminders:', error);
      }
    }, intervalMs);
  }
}