import { NextFunction, Request, Response } from 'express';
import { Types } from 'mongoose';
import validator from 'validator';
import { z } from 'zod';
import asyncHandler from '../../shared/middleware/async';
import ErrorResponse from '../../utils/errorResponse';
import Token from '../token/token.model';
import User, { UserDocument } from '../user/user.model';
import authService, { resetUserPassword } from './auth.service';
import {sendEmail} from '../../utils/email';

const emailSchema = z.string().email('Invalid email format');
const passwordSchema = z
  .string()
  .min(6, 'Password must be at least 6 characters');

const registerSchema = z.object({
  first_name: z.string().min(1, 'First name is required'),
  last_name: z.string().min(1, 'Last name is required'),
  email: emailSchema,
  password: passwordSchema,
  role: z.string().optional(),
});

const loginSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
});

const forgotPasswordSchema = z.object({
  email: emailSchema,
});

const resetPasswordSchema = z.object({
  query: z.object({
    token: z.string().min(1, 'Token is required'),
    id: z
      .string()
      .min(1, 'ID is required')
      .refine(val => Types.ObjectId.isValid(val), {
        message: 'Invalid ID format',
      }),
  }),
  body: z.object({
    password: passwordSchema,
  }),
});

const resendVerificationSchema = z.object({
  email: emailSchema,
});

interface RegisterBody {
  first_name: string;
  last_name: string;
  email: string;
  password: string;
  role?: string;
}

interface LoginBody {
  email: string;
  password: string;
}

interface AuthenticatedRequest extends Request {
  user?: { id: string }; // Define the user property with an id
}

/**
 * @route   POST /api/v1/auth/register
 * @desc    Register a new user
 * @access  Public
 */

export const register = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    // Validate request body
    const parseResult = registerSchema.safeParse(req.body);
    if (!parseResult.success) {
      return next(new ErrorResponse(parseResult.error.message, 400));
    }

    const { first_name, last_name, email, password, role } = parseResult.data;

    // Check if user already exists (case insensitive)
    const existingUser = await User.findOne({ email }).collation({
      locale: 'en',
      strength: 2,
    });

    if (existingUser) {
      return next(new ErrorResponse('Email already registered', 400));
    }

    // Create user with validated data
    const user: UserDocument = await User.create({
      first_name,
      last_name,
      email,
      password,
      role: role ?? 'user',
    });

    // Send verification email
    await authService.sendVerificationEmail(user);

    // Remove sensitive data from response
    const userWithoutPassword = user.toObject();
    delete userWithoutPassword.password;

    res.status(201).json({
      success: true,
      data: { user: userWithoutPassword },
      message:
        'Registration successful! Please check your email to verify your account.',
    });
  },
);

/**
 * @route   POST /api/v1/auth/login
 * @desc    Login a user
 * @access  Public
 */
export const login = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    // Validate request body
    const parseResult = loginSchema.safeParse(req.body);
    if (!parseResult.success) {
      return next(new ErrorResponse(parseResult.error.message, 400));
    }

    const { email, password } = parseResult.data;

    // Find user with case-insensitive email match
    const user = await User.findOne({ email })
      .collation({ locale: 'en', strength: 2 })
      .select('+password');

    if (!user) {
      // Use consistent error message for security
      return next(new ErrorResponse('Invalid credentials', 401));
    }

    // Check password
    const isMatched = await authService.matchPassword(password, user);

    if (!isMatched) {
      // Use consistent error message for security
      return next(new ErrorResponse('Invalid credentials', 401));
    }

    // Generate token
    const token = authService.generateToken(user);

    // Remove sensitive data from response
    const userWithoutPassword = user.toObject();
    delete userWithoutPassword.password;

    // Set token in cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      sameSite: 'none',
    });

    res.status(200).json({
      success: true,
      data: { user: userWithoutPassword, token },
    });
  },
);

/**
 * @route   POST /api/v1/auth/admin/login
 * @desc    Admin Login with dashboard access check
 * @access  Public
 */
export const adminLogin = asyncHandler(
  async (
    req: Request<{}, {}, LoginBody>,
    res: Response,
    next: NextFunction,
  ) => {
    let { email, password } = req.body;
    // Trim and sanitize inputs
    email = validator.trim(email ?? '').toLowerCase();
    password = validator.trim(password ?? '');

    // Input validation
    if (!email || !password) {
      return next(
        new ErrorResponse('Please provide an email and password', 400),
      );
    }

    // Validate email format
    if (!validator.isEmail(email)) {
      return next(new ErrorResponse('Invalid email format', 400));
    }

    // Find user with case-insensitive email match
    const user = await User.findOne({ email })
      .collation({ locale: 'en', strength: 2 })
      .select('+password');

    if (!user) {
      return next(new ErrorResponse('Invalid credentials', 401));
    }

    // Check password
    const isMatched = await authService.matchPassword(password, user);

    if (!isMatched) {
      return next(new ErrorResponse('Invalid credentials', 401));
    }

    // Check for admin dashboard access permission
    try {
      const hasAdminAccess = await authService.checkAdminAccess(user._id);
      if (!hasAdminAccess) {
        return next(
          new ErrorResponse('Unauthorized access to admin dashboard', 403),
        );
      }
    } catch (error) {
      console.error('Admin access verification error:', error);
      return next(new ErrorResponse('Admin access verification failed', 500));
    }

    // Generate token
    const token = authService.generateToken(user);

    // Remove sensitive data from response
    const userWithoutPassword = user.toObject();
    delete userWithoutPassword.password;

    // Set admin token cookie
    res.cookie('admin_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
      path: '/',
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    });

    // Set regular token cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
      path: '/',
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    });

    res.status(200).json({
      success: true,
      data: { user: userWithoutPassword },
    });
  },
);

/**
 * @route   POST /api/v1/auth/logout
 * @desc    Logout current user
 * @access  Public
 */

export const logout = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    res.cookie('token', '', {
      httpOnly: true,
      expires: new Date(0), // set the cookie to expire immediately
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
    });
    res.cookie('admin_token', '', {
      httpOnly: true,
      expires: new Date(0), // set the cookie to expire immediately
      secure: process.env.NODE_ENV === 'production', // Uncomment for production
      sameSite: 'none',
    });
    res.cookie('org_token', '', {
      httpOnly: true,
      expires: new Date(0), // set the cookie to expire immediately
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
    });

    res.status(200).json({
      success: true,
      message: 'Logged out successfully',
    });
  },
);

/**
 * @route   GET /api/v1/auth/me
 * @desc    Get current authenticated user
 * @access  Private
 */
export const getMe = asyncHandler(
  async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user?.id) {
      return next(new ErrorResponse('User not authenticated', 401));
    }

    const user = await User.findById(req.user.id).select(
      '-password -verificationToken -verificationTokenExpires',
    );

    if (!user) {
      return next(new ErrorResponse('User not found', 404));
    }

    // If it's an admin request, check admin access
    if (req.cookies.admin_token) {
      try {
        const hasAdminAccess = await authService.checkAdminAccess(user._id);
        if (!hasAdminAccess) {
          return next(new ErrorResponse('Not authorized as admin', 403));
        }
      } catch (error) {
        console.error('Admin access verification error:', error);
        return next(new ErrorResponse('Admin access verification failed', 500));
      }
    }

    // If it's an organization/turf owner request, check organization access
    if (req.cookies.org_token && req.params.organizationId) {
      
        const hasOrgAccess = await authService.checkUserRoleInOrganization(
          user._id,
          req.params.organizationId,
        );
        if (!hasOrgAccess) {
          return next(
            new ErrorResponse('Not authorized as organization owner', 403),
          );
        }
     
    }

    res.status(200).json({
      success: true,
      data: user,
    });
  },
);

/**
 * @route   POST /api/v1/auth/forgot-password
 * @desc    Request a password reset email
 * @access  Public
 */

export const forgotPassword = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    // Validate request body
    const parseResult = forgotPasswordSchema.safeParse(req.body);
    if (!parseResult.success) {
      return next(new ErrorResponse(parseResult.error.message, 400));
    }

    const { email } = parseResult.data;

    const user = await User.findOne({ email });

    if (!user) {
      return next(new ErrorResponse('User not found', 404));
    }

    let token = await Token.findOne({ userId: user._id });
    if (token) {
      await token.deleteOne();
    }

    try {
      const result = await authService.sendPasswordResetEmail(user);
      res.status(200).json(result);
    } catch (error: unknown) {
      // Log the error for debugging
      console.error('Password reset email error:', error);

      // Determine if it's a known error type
      if (error instanceof Error) {
        return next(
          new ErrorResponse(
            `Failed to send password reset email: ${error.message}`,
            500,
          ),
        );
      }

      // Generic error for unknown error types
      return next(
        new ErrorResponse(
          'An unexpected error occurred while sending reset email',
          500,
        ),
      );
    }
  },
);

/**
 * @route   POST /api/v1/auth/reset-password/?token=token&id=id
 * @desc    Reset password
 * @access  Public
 */

export const resetPassword = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    // Validate both query params and body
    const parseResult = resetPasswordSchema.safeParse({
      query: req.query,
      body: req.body,
    });

    if (!parseResult.success) {
      return next(new ErrorResponse(parseResult.error.message, 400));
    }

    const { token, id } = parseResult.data.query;
    const { password } = parseResult.data.body;

    // Call the modular service function
    const response = await resetUserPassword(id, token, password);

    res.status(200).json(response);
  },
);

/**
 * @route   POST /api/v1/auth/verify-email/?token=token&id=id
 * @desc    Reset password
 * @access  Public
 */
export const verifyEmail = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    // Define Zod schema for query parameters validation
    const verifyEmailSchema = z.object({
      token: z.string().min(1, 'Token is required'),
      id: z
        .string()
        .min(1, 'ID is required')
        .refine(val => Types.ObjectId.isValid(val), {
          message: 'Invalid ID format',
        }),
    });

    // Validate and parse query parameters
    const parseResult = verifyEmailSchema.safeParse(req.query);

    if (!parseResult.success) {
      return next(new ErrorResponse('Invalid verification parameters', 400));
    }

    const { token, id } = parseResult.data;

    // Find the user by validated ID
    const user = await User.findById(id);

    if (!user) {
      return next(new ErrorResponse('User not found', 404));
    }

    // Check if user is already verified
    if (user.isVerified) {
      return res.status(200).json({
        success: true,
        message: 'Email already verified',
      });
    }

    // Check if the token matches and is not expired
    if (
      !user.verificationToken ||
      user.verificationToken !== token ||
      !user.verificationTokenExpires ||
      new Date() > user.verificationTokenExpires
    ) {
      return next(new ErrorResponse('Invalid or expired token', 400));
    }

    // Mark the user as verified
    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpires = undefined;
    await user.save();

    // Create HTML content for the success notification (from new method)
    const htmlContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eaeaea; border-radius: 5px; background-color: #f9f9f9;">
        <h2 style="color: #4a9d61; text-align: center; margin-bottom: 20px;">Email Verification Successful</h2>
        
        <div style="background-color: #ffffff; border: 1px solid #eaeaea; border-radius: 3px; padding: 15px; margin-bottom: 20px;">
          <h3 style="color: #333; margin-top: 0;">Dear ${user.first_name || 'Valued User'},</h3>
          <p style="font-size: 16px; line-height: 1.6; margin-bottom: 20px;">
            Your email address has been successfully verified. Thank you for completing this important security step.
          </p>
          
          <div style="background-color: #eafbf0; border-left: 4px solid #4a9d61; padding: 15px; margin: 20px 0;">
            <p style="font-size: 15px; margin: 0;">
              Your account is now fully activated, and you can access all features of TurfMania.
            </p>
          </div>
        </div>
        
        <div style="text-align: center; margin-top: 25px;">
          <a href="${process.env.CLIENT_URL}/sign-in" style="background-color: #4a9d61; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold; display: inline-block;">Login to Your Account</a>
        </div>
        
        <p style="font-size: 15px; line-height: 1.6; color: #555; margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee;">
          We're excited to have you join our community! If you have any questions or need assistance, please contact our support team.
        </p>
      </div>
    `;

    // Send confirmation email (from new method)
    await sendEmail(
      user.email,
      'Email Verification Successful - TurfMania',
      'Your email address has been successfully verified. Your account is now fully activated.',
      htmlContent
    );

    res.status(200).json({
      success: true,
      message: 'Email verified successfully!',
    });
  },
);

/**
 * @route   POST /api/v1/auth/resend-verification
 * @desc    Resend verification email to user
 * @access  Public
 */
export const resendVerificationEmail = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    // Validate request body
    const parseResult = resendVerificationSchema.safeParse(req.body);
    if (!parseResult.success) {
      return next(new ErrorResponse(parseResult.error.message, 400));
    }

    const { email } = parseResult.data;

    const user = await User.findOne({ email }).collation({
      locale: 'en',
      strength: 2,
    });

    if (!user) {
      return next(new ErrorResponse('User with this email not found', 404));
    }

    // Check if user is already verified
    if (user.isVerified) {
      return next(new ErrorResponse('Email is already verified', 400));
    }

    // Send verification email
    await authService.sendVerificationEmail(user);

    res.status(200).json({
      success: true,
      message: 'Verification email has been sent. Please check your inbox.',
    });
  },
);
