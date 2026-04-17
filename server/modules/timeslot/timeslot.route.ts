import { Router } from 'express';

import TimeSlotController from './timeslot.controller';
import { standardApiLimiter } from '../../utils/rateLimiter';
import { protect } from '../auth/auth.middleware';

const router = Router();

const timeslotController = new TimeSlotController();
router.post('/generate',protect, timeslotController.generateTimeSlot);
router.get('/', timeslotController.getTimeSlot);
router.get('/available/:turfId', timeslotController.getAvailableTimeSlot);
router.put('/:id',protect,timeslotController.updateTimeSlot)

export default router;
