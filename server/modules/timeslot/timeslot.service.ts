import mongoose from 'mongoose';
import { Turf } from '../turf/turf.model';
import { ITimeSlot, TimeSlot } from './timeslot.model';

export default class TimeSlotService {
  async generateTimeSlots(
    turfId: string,
    startDate: Date,
    endDate: Date,
    slotDuration: number = 60,
  ): Promise<ITimeSlot[]> {
    console.log('Checking for existing slots...');
    const turf = await Turf.findById(turfId);
    if (!turf) throw new Error('Turf not found');

    // Format dates properly
    const startDateTime = new Date(startDate);
    startDateTime.setHours(0, 0, 0, 0);

    const endDateTime = new Date(endDate);
    endDateTime.setHours(23, 59, 59, 999);

    // Check if any slots already exist in the specified date range
    const existingSlots = await TimeSlot.find({
      turf: turfId,
      start_time: { $gte: startDateTime },
      end_time: { $lte: endDateTime }
    });

    // If any slots exist in this range, throw an error
    if (existingSlots.length > 0) {
      throw new Error(`Timeslots already exist for this turf between ${startDate} and ${endDate}`);
    }

    // Proceed with slot generation since no existing slots were found
    const slots = [];
    const currentDate = new Date(startDateTime);

    while (currentDate <= endDateTime) {
      const dayOfWeek = currentDate.getDay();
      const operatingHours = turf.operatingHours.find(
        hours => Number(hours.day) === dayOfWeek,
      );

      if (operatingHours) {
        let [openHour, openMinute] = operatingHours.open.split(':').map(Number);
        let [closeHour, closeMinute] = operatingHours.close
          .split(':')
          .map(Number);

        const start = new Date(currentDate);
        start.setHours(openHour, openMinute, 0);

        const end = new Date(currentDate);
        end.setHours(closeHour, closeMinute, 0);

        while (start < end) {
          const slotEnd = new Date(start);
          slotEnd.setMinutes(start.getMinutes() + slotDuration);

          if (slotEnd <= end) {
            slots.push({
              turf: new mongoose.Types.ObjectId(turfId),
              start_time: new Date(start),
              end_time: new Date(slotEnd),
              is_available: true,
            });
          }

          start.setMinutes(start.getMinutes() + slotDuration);
        }
      }

      // Move to next day
      currentDate.setDate(currentDate.getDate() + 1);
      currentDate.setHours(0, 0, 0, 0);
    }

    // Create all slots at once 
    if (slots.length > 0) {
      await TimeSlot.insertMany(slots);
      console.log(`Successfully created ${slots.length} time slots`);
    } else {
      console.log('No slots to create');
    }

    return await this.getTimeSlots({
      turf: turfId,
      start_time: { $gte: startDateTime },
      end_time: { $lte: endDateTime },
    });
  }

  async getTimeSlots(filters = {}): Promise<ITimeSlot[]> {
    return await TimeSlot.find(filters).sort('start_time');
  }

  async getAvailableTimeSlots(
    turfId: string,
    date: Date,
  ): Promise<ITimeSlot[]> {
    const startOfDay = new Date(date);
    startOfDay.setHours(0, 0, 0, 0);

    const endOfDay = new Date(date);
    endOfDay.setHours(23, 59, 59, 999);

    // Get current time
    const currentTime = new Date();

    return await TimeSlot.find({
      turf: turfId,
      start_time: {
        $gte: currentTime > startOfDay ? currentTime : startOfDay,
        $lte: endOfDay
      },
      is_available: true,
    }).sort('start_time');
  }

  async updateTimeSlot(
    id: string,
    updateData: Partial<ITimeSlot>,
  ): Promise<ITimeSlot | null> {
    return await TimeSlot.findByIdAndUpdate(id, updateData, { new: true });
  }

  async deleteTimeSlots(filters = {}): Promise<{ deletedCount: number }> {
    const result = await TimeSlot.deleteMany(filters);
    return { deletedCount: result.deletedCount ?? 0 };
  }
}