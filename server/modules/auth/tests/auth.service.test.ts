import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import User, { UserDocument } from '../../user/user.model';
import Token from '../../token/token.model';
import UserRoleAssignment from '../../role_assignment/userRoleAssignment.model';
import ErrorResponse from '../../../utils/errorResponse';
import { sendEmail } from '../../../utils/email';

// Set environment variables before importing the service
process.env.JWT_SECRET = 'test-secret';
process.env.JWT_EXPIRE = '30d';
process.env.CLIENT_URL = 'http://localhost:3000';

// Import after setting environment variables
import authService, { resetUserPassword } from '../auth.service';

// Mock dependencies
jest.mock('jsonwebtoken');
jest.mock('bcryptjs');
jest.mock('../../../utils/email');
jest.mock('../../user/user.model');
jest.mock('../../token/token.model');
jest.mock('../../role_assignment/userRoleAssignment.model');
jest.mock('crypto', () => ({
  randomBytes: jest.fn().mockReturnValue({
    toString: jest.fn().mockReturnValue('mock-verification-token')
  })
}));

describe('AuthService', () => {
  let originalEnv: NodeJS.ProcessEnv;
  
  beforeEach(() => {
    originalEnv = { ...process.env };
    jest.clearAllMocks();
  });
  
  afterEach(() => {
    process.env = originalEnv;
  });

  describe('constructor', () => {
    // We'll test the constructor by using jest.isolateModules to load the module in isolation
    it('should throw error if JWT_SECRET is missing', () => {
      jest.isolateModules(() => {
        delete process.env.JWT_SECRET;
        expect(() => {
          require('../auth.service');
        }).toThrow('JWT configuration is missing');
      });
    });

    it('should throw error if JWT_EXPIRE is missing', () => {
      jest.isolateModules(() => {
        delete process.env.JWT_EXPIRE;
        expect(() => {
          require('../auth.service');
        }).toThrow('JWT configuration is missing');
      });
    });
    
    // The initialization test isn't needed since we know the service is initialized
    // because we're testing other methods on it
  });

  describe('generateToken', () => {
    it('should generate a JWT token', () => {
      const user = { _id: 'user123' } as UserDocument;
      (jwt.sign as jest.Mock).mockReturnValue('generated-token');
      
      const token = authService.generateToken(user);
      
      expect(token).toBe('generated-token');
      expect(jwt.sign).toHaveBeenCalledWith(
        { id: 'user123' },
        'test-secret',
        { expiresIn: '30d' }
      );
    });
  });

  describe('matchPassword', () => {
    it('should return true when passwords match', async () => {
      const user = { password: 'hashed-password' } as UserDocument;
      (bcrypt.compare as jest.Mock).mockResolvedValue(true);
      
      const result = await authService.matchPassword('password123', user);
      
      expect(result).toBe(true);
      expect(bcrypt.compare).toHaveBeenCalledWith('password123', 'hashed-password');
    });
    
    it('should return false when passwords do not match', async () => {
      const user = { password: 'hashed-password' } as UserDocument;
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);
      
      const result = await authService.matchPassword('wrong-password', user);
      
      expect(result).toBe(false);
      expect(bcrypt.compare).toHaveBeenCalledWith('wrong-password', 'hashed-password');
    });
  });

  describe('sendVerificationEmail', () => {
    it('should generate token and send verification email', async () => {
      const user = {
        _id: 'user123',
        email: 'test@example.com',
        save: jest.fn().mockResolvedValue(true)
      } as unknown as UserDocument;
      (sendEmail as jest.Mock).mockResolvedValue(true);
      
      await authService.sendVerificationEmail(user);
      
      expect(user.verificationToken).toBe('mock-verification-token');
      expect(user.verificationTokenExpires).toBeInstanceOf(Date);
      expect(user.save).toHaveBeenCalled();
      expect(sendEmail).toHaveBeenCalledWith(
        'test@example.com',
        'Verify Your Email - TurfMania',
        expect.stringContaining('http://localhost:3000/verify-email?token=mock-verification-token&id=user123'),
        expect.any(String)
      );
    });
  });

  describe('checkUserRoleInOrganization', () => {
    it('should return role assignment if user has access', async () => {
      const userId = 'user123';
      const orgId = 'org456';
      const roleAssignment = { _id: 'role789', role: 'owner' };
      
      (UserRoleAssignment.findOne as jest.Mock).mockResolvedValue(roleAssignment);
      
      const result = await authService.checkUserRoleInOrganization(userId, orgId);
      
      expect(result).toEqual(roleAssignment);
      expect(UserRoleAssignment.findOne).toHaveBeenCalledWith({
        userId,
        scope: 'organization',
        scopeId: orgId
      });
    });
    
    it('should throw error if user does not have access', async () => {
      const userId = 'user123';
      const orgId = 'org456';
      
      (UserRoleAssignment.findOne as jest.Mock).mockResolvedValue(null);
      
      await expect(authService.checkUserRoleInOrganization(userId, orgId))
        .rejects
        .toThrow(new ErrorResponse('You do not have access to this organization dashboard', 403));
    });
  });

  describe('checkAdminAccess', () => {
    it('should return true if user has admin access', async () => {
      const userId = new mongoose.Types.ObjectId('507f1f77bcf86cd799439011');
      
      (UserRoleAssignment.findOne as jest.Mock).mockReturnValue({
        populate: jest.fn().mockResolvedValue({
          roleId: {
            permissions: [
              { name: 'access_admin_dashboard' },
              { name: 'other_permission' }
            ]
          }
        })
      });
      
      const result = await authService.checkAdminAccess(userId);
      
      expect(result).toBe(true);
    });
    
    it('should return false if user has no admin access permission', async () => {
      const userId = new mongoose.Types.ObjectId('507f1f77bcf86cd799439011');
      
      (UserRoleAssignment.findOne as jest.Mock).mockReturnValue({
        populate: jest.fn().mockResolvedValue({
          roleId: {
            permissions: [
              { name: 'other_permission' }
            ]
          }
        })
      });
      
      const result = await authService.checkAdminAccess(userId);
      
      expect(result).toBe(false);
    });
    
    it('should return false if user has no role assignments', async () => {
      const userId = new mongoose.Types.ObjectId('507f1f77bcf86cd799439011');
      
      (UserRoleAssignment.findOne as jest.Mock).mockReturnValue({
        populate: jest.fn().mockResolvedValue(null)
      });
      
      const result = await authService.checkAdminAccess(userId);
      
      expect(result).toBe(false);
    });
    
    it('should return false if error occurs', async () => {
      const userId = new mongoose.Types.ObjectId('507f1f77bcf86cd799439011');
      
      (UserRoleAssignment.findOne as jest.Mock).mockReturnValue({
        populate: jest.fn().mockRejectedValue(new Error('DB error'))
      });
      
      const result = await authService.checkAdminAccess(userId);
      
      expect(result).toBe(false);
    });
  });
});

describe('resetUserPassword function', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    process.env.CLIENT_URL = 'http://localhost:3000';
  });
  
  it('should reset password when token is valid', async () => {
    const id = 'user123';
    const token = 'valid-token';
    const newPassword = 'newSecurePassword123';
    
    const tokenRecord = {
      _id: 'token123',
      userId: id,
      token: 'hashed-token'
    };
    
    const user = {
      _id: id,
      email: 'user@example.com',
      password: 'old-password',
      save: jest.fn().mockResolvedValue(true)
    };
    
    (Token.findOne as jest.Mock).mockResolvedValue(tokenRecord);
    (bcrypt.compare as jest.Mock).mockResolvedValue(true);
    (User.findById as jest.Mock).mockResolvedValue(user);
    (Token.findByIdAndDelete as jest.Mock).mockResolvedValue(tokenRecord);
    (sendEmail as jest.Mock).mockResolvedValue(true);
    
    const result = await resetUserPassword(id, token, newPassword);
    
    expect(result).toEqual({ success: true, message: 'Password reset successful!' });
    expect(user.password).toBe(newPassword);
    expect(user.save).toHaveBeenCalled();
    expect(Token.findByIdAndDelete).toHaveBeenCalledWith('token123');
    expect(sendEmail).toHaveBeenCalledWith(
      'user@example.com',
      'Password Reset Successful - TurfMania',
      expect.stringContaining('Your password has been successfully reset'),
      expect.any(String)
    );
  });
  
  it('should throw error if token not found', async () => {
    (Token.findOne as jest.Mock).mockResolvedValue(null);
    
    await expect(resetUserPassword('user123', 'token', 'newpass'))
      .rejects
      .toThrow(new ErrorResponse('Invalid or expired token', 400));
  });
  
  it('should throw error if token does not match', async () => {
    const tokenRecord = {
      userId: 'user123',
      token: 'hashed-token'
    };
    
    (Token.findOne as jest.Mock).mockResolvedValue(tokenRecord);
    (bcrypt.compare as jest.Mock).mockResolvedValue(false);
    
    await expect(resetUserPassword('user123', 'wrong-token', 'newpass'))
      .rejects
      .toThrow(new ErrorResponse('Invalid or expired token', 400));
  });
  
  it('should throw error if user not found', async () => {
    const tokenRecord = {
      userId: 'user123',
      token: 'hashed-token'
    };
    
    (Token.findOne as jest.Mock).mockResolvedValue(tokenRecord);
    (bcrypt.compare as jest.Mock).mockResolvedValue(true);
    (User.findById as jest.Mock).mockResolvedValue(null);
    
    await expect(resetUserPassword('user123', 'token', 'newpass'))
      .rejects
      .toThrow(new ErrorResponse('User not found', 404));
  });
});