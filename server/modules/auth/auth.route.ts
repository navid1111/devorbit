import express from 'express';
import {
  adminLogin,
  forgotPassword,
  getMe,
  login,
  logout,
  register,
  resetPassword,
  verifyEmail,
  resendVerificationEmail
} from './auth.controller';
import { protect } from './auth.middleware';
import { authLimiter } from '../../utils/rateLimiter';

const router = express.Router();

router.post('/register', register);

router.post('/login', login);

router.post('/logout', logout);

router.get('/me', protect, getMe);

router.post('/forgot-password', forgotPassword);

router.post('/reset-password', resetPassword);

router.get('/verify-email', verifyEmail);

router.post('/admin/login', adminLogin)

router.post('/resend-verification', resendVerificationEmail);
export default router;
