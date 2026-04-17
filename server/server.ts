import app from './app';
import OrganizationRequestService from './modules/organization-request/organization-request.service';
import BookingService from './modules/booking/booking.service';

const port = process.env.PORT ?? 3000;

// Start the server
const server = app.listen(port, () => {
  console.log(`Server app listening on port ${port}!`);

  // Start periodic services
  const orgRequestService = new OrganizationRequestService();
  try {
    orgRequestService.startPeriodicCleanup(); // Default 2h timeout, 1h interval
  }
  catch (error) {
    console.error('Error starting periodic cleanup:', error);
  }
  const bookingService = new BookingService();
  try {
    bookingService.startPeriodicReminders(); // Default 5m interval
  }
  catch (error) {
    console.error('Error starting periodic reminders:', error);
  }
});

// Handle shutdown gracefully
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});