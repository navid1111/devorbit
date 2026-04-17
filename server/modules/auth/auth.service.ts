import bcrypt from "bcryptjs";
import crypto from "crypto";
import jwt, { SignOptions } from "jsonwebtoken";
import {Types } from "mongoose";
import { sendEmail } from "../../utils/email";
import ErrorResponse from "../../utils/errorResponse";
import Token from "../token/token.model";
import { PermissionScope } from "./../permission/permission.model";
import User, { UserDocument } from "./../user/user.model";
import UserRoleAssignment from "../role_assignment/userRoleAssignment.model";

interface IPermission {
  _id: Types.ObjectId;
  name: string;
}

class AuthService {
  private readonly JWT_SECRET: string;

  constructor() {
    if (!process.env.JWT_SECRET || !process.env.JWT_EXPIRE) {
      throw new Error("JWT configuration is missing");
    }
    this.JWT_SECRET = process.env.JWT_SECRET;
  }

  /** @desc generate token for user **/

  public generateToken(user: UserDocument): string {
    const signOptions: SignOptions = {
      expiresIn: "30d",
    };
    return jwt.sign(
      {
        id: user._id,
      },
      this.JWT_SECRET,
      signOptions
    );
  }

  /** @desc match user entered password to hash password in database **/

  public async matchPassword(enteredPassword: string, user: UserDocument) {
    return await bcrypt.compare(enteredPassword, user.password);
  }

  /** @desc Generate verification token and send verification email **/

  public async sendVerificationEmail(user: UserDocument) {
    // Generate verification token
    const verificationToken = crypto.randomBytes(20).toString("hex");
    user.verificationToken = verificationToken;
    user.verificationTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
    await user.save();

    // Send verification email
    const verificationUrl = `${process.env.CLIENT_URL}/verify-email?token=${verificationToken}&id=${user._id}`;
    
    const htmlContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eaeaea; border-radius: 5px; background-color: #f9f9f9;">
        <h2 style="color: #4a9d61; text-align: center; margin-bottom: 20px;">Welcome to TurfMania!</h2>
        
        <div style="background-color: #ffffff; border: 1px solid #eaeaea; border-radius: 3px; padding: 15px; margin-bottom: 20px;">
          <h3 style="color: #333; margin-top: 0;">Dear ${user.first_name || 'Valued User'},</h3>
          <p style="font-size: 16px; line-height: 1.6; margin-bottom: 20px;">
            Thank you for registering with TurfMania. To complete your registration and access all features, please verify your email address.
          </p>
          
          <div style="background-color: #f8f9fa; border-radius: 3px; padding: 15px; margin: 20px 0; text-align: center;">
            <p style="font-size: 15px; margin-bottom: 15px; color: #333;">
              Your verification link will expire in <strong>24 hours</strong>.
            </p>
          </div>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
          <a href="${verificationUrl}" style="background-color: #4a9d61; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold; display: inline-block;">Verify My Email</a>
        </div>
        
        <p style="font-size: 14px; color: #666; margin-top: 20px;">
          If you can't click the button, copy and paste this link into your browser:
        </p>
        <div style="background-color: #f8f9fa; border: 1px solid #eaeaea; border-radius: 3px; padding: 10px; margin: 10px 0; word-break: break-all;">
          <a href="${verificationUrl}" style="color: #4a9d61; text-decoration: none; font-size: 14px;">${verificationUrl}</a>
        </div>
        
        <p style="font-size: 14px; color: #666; margin-top: 20px;">
          If you did not create an account, please ignore this email.
        </p>
      </div>
    `;

    await sendEmail(
      user.email,
      "Verify Your Email - TurfMania",
      `Please verify your email by clicking the link: ${verificationUrl}\nThis link is valid for 24 hours.`,
      htmlContent
    );
  }

  /** @desc Password reset email sender **/

  public async sendPasswordResetEmail(user: UserDocument) {
    //generate reset token
    const resetToken = crypto.randomBytes(32).toString("hex");

    const salt = 10;
    const hashedToken = await bcrypt.hash(resetToken, Number(salt));

    //save token in database
    await Token.create({ userId: user._id, token: hashedToken });

    //create reset url
    const resetUrl = `${process.env.CLIENT_URL}/reset-password/?token=${resetToken}&id=${user._id}`;
    
    const htmlContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eaeaea; border-radius: 5px; background-color: #f9f9f9;">
        <h2 style="color: #4a9d61; text-align: center; margin-bottom: 20px;">Password Reset Request</h2>
        <p style="font-size: 16px; line-height: 1.6; margin-bottom: 20px;">We received a request to reset your password. If you didn't make this request, you can safely ignore this email.</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${resetUrl}" style="background-color: #4a9d61; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold; display: inline-block;">Reset My Password</a>
        </div>
        <p style="font-size: 14px; color: #666; margin-top: 20px;">This reset link will expire in 10 minutes for security reasons.</p>
        <p style="font-size: 14px; color: #666;">If you can't click the button, copy and paste this link into your browser: ${resetUrl}</p>
      </div>
    `;

    // Send reset email
    return await sendEmail(
      user.email,
      "Password Reset Request - TurfMania",
      `Click the link to reset your password:\n\n${resetUrl}\n\nThis link is valid for 10 minutes.`,
      htmlContent
    );
  }

  /** @desc Check if user has organization dashboard access **/
  public async checkUserRoleInOrganization(
    userId: string,
    organizationId: string
  ) {
    console.log("userId", userId);
    console.log("organizationId", organizationId);
    const roleAssignment = await UserRoleAssignment.findOne({
      userId,
      scope: "organization",
      scopeId: organizationId,
    });
    console.log("roleAssignment", roleAssignment);

    if (!roleAssignment) {
      throw new ErrorResponse(
        "You do not have access to this organization dashboard",
        403
      );
    }

    return roleAssignment;
  }

  /** @desc Check if user has admin dashboard access **/
  public async checkAdminAccess(userId: Types.ObjectId): Promise<boolean> {
    try {
      const assignments = await UserRoleAssignment.findOne({
        userId,
        scope: PermissionScope.GLOBAL,
      }).populate<{
        roleId: {
          permissions: IPermission[];
        };
      }>({
        path: "roleId",
        select: "permissions",
        populate: {
          path: "permissions",
          select: "_id name",
        },
      });

      if (!assignments?.roleId?.permissions?.length) {
        return false;
      }

      return assignments.roleId.permissions.some(
        (permission) => permission.name === "access_admin_dashboard"
      );
    } catch (error) {
      console.error("Error checking admin access:", error);
      return false;
    }
  }
}

/** @desc matches hashed token and saves new password **/

export const resetUserPassword = async (
  id: string,
  token: string,
  newPassword: string
) => {
  // Check if token exists in DB
  const tokenRecord = await Token.findOne({ userId: id });
  if (!tokenRecord) {
    throw new ErrorResponse("Invalid or expired token", 400);
  }

  // Compare provided token with hashed token in DB
  const isMatch = await bcrypt.compare(token, tokenRecord.token);
  if (!isMatch) {
    throw new ErrorResponse("Invalid or expired token", 400);
  }

  // Find user by ID
  const user = await User.findById(id);
  if (!user) {
    throw new ErrorResponse("User not found", 404);
  }

  // Update user password
  user.password = newPassword;
  await user.save();

  // Delete used token from DB
  await Token.findByIdAndDelete(tokenRecord._id);

  // Send success email
  const htmlContent = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eaeaea; border-radius: 5px; background-color: #f9f9f9;">
      <h2 style="color: #4a9d61; text-align: center; margin-bottom: 20px;">Password Reset Successful</h2>
      <p style="font-size: 16px; line-height: 1.6; margin-bottom: 20px;">Your password has been successfully updated.</p>
      <div style="background-color: #eafbf0; border-left: 4px solid #4a9d61; padding: 15px; margin: 20px 0;">
        <p style="font-size: 15px; color: #333; margin: 0;">If you did not perform this action, please contact our support team immediately.</p>
      </div>
      <div style="text-align: center; margin-top: 30px;">
        <a href="${process.env.CLIENT_URL}/sign-in" style="background-color: #4a9d61; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold; display: inline-block;">Login to Your Account</a>
      </div>
    </div>
  `;

  await sendEmail(
    user.email,
    "Password Reset Successful - TurfMania",
    "Your password has been successfully reset. If you did not perform this action, please contact support immediately.",
    htmlContent
  );

  return { success: true, message: "Password reset successful!" };
};

export const authService = new AuthService();
export default authService;