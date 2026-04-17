import express from 'express';
import { protect, checkPermission } from '../auth/auth.middleware';
import BookingController from './booking.controller';
import { standardApiLimiter } from '../../utils/rateLimiter';

const router = express.Router();

// Initialize controller
const bookingController = new BookingController();

// User Endpoints
router.post(
    '/',

    protect,
    bookingController.createBooking
);

router.put(
    '/:id/complete-stripe',

    protect,
    bookingController.completeStripeBooking
);

router.put(
    '/:id/complete-cash',

    protect,
    bookingController.completeCashBooking
);

router.get(
    '/user',

    protect,
    bookingController.getUserBookings
);
router.get(
    '/:id',

    protect,
    bookingController.getBooking
);

// Admin Endpoints
router.get(
    '/',

    protect,
    checkPermission('global_manage_bookings'),
    bookingController.getAllBookings
);

router.get(
    '/admin/:id',

    protect,
    checkPermission('global_manage_bookings'),
    bookingController.getBookingAsAdmin
);

// New Turf-specific Bookings
router.get(
    '/turf/:turfId',

    protect,
    checkPermission('manage_bookings'),
    bookingController.getTurfBookings
);

// Earnings Reports
router.get(
    '/turf/:turfId/monthly-earnings',

    protect,
    checkPermission('manage_bookings'),
    bookingController.getTurfMonthlyEarnings
);

router.get(
    '/turf/:turfId/current-month-earnings',

    protect,
    checkPermission('manage_bookings'),
    bookingController.getTurfCurrentMonthEarnings
);

router.get(
    '/organization/:organizationId/current-month-earnings',

    protect,
    checkPermission('manage_bookings'),
    bookingController.getOrganizationCurrentMonthEarnings
);

export default router;