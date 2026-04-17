import mongoose from 'mongoose';
import validator from 'validator';

import { z } from 'zod';
import { uploadImage } from '../../utils/cloudinary';
import { sendEmail } from '../../utils/email';
import ErrorResponse from '../../utils/errorResponse';
import { validateId } from '../../utils/validation';
import FaciltyService from '../facility/facility.service';
import User from '../user/user.model';
import OrganizationRequest, {
  IOrganizationRequest,
  RequestStatus,
} from './organization-request.model';

interface CreateRequestDto {
  organizationName: string;
  facilities: string[];
  location: {
    place_id: string;
    address: string;
    coordinates: {
      type: 'Point';
      coordinates: [number, number];
    };
    area?: string;
    sub_area?: string;
    city: string;
    post_code?: string;
  };
  contactPhone: string;
  ownerEmail: string;
  requestNotes?: string;
  orgContactPhone: string;
  orgContactEmail: string;
}

interface ProcessingResult {
  success: boolean;
  message: string;
  data?: any;
}

export interface RequestFilters {
  status?: RequestStatus | RequestStatus[];
  fromDate?: Date;
  toDate?: Date;
  requesterEmail?: string;
  ownerEmail?: string;
  sortBy?: 'createdAt' | 'updatedAt' | 'organizationName';
  sortOrder?: 'asc' | 'desc';
}

export interface PaginationOptions {
  page: number;
  limit: number;
}

export interface RequestsResult {
  total: number;
  page: number;
  pages: number;
  requests: IOrganizationRequest[];
}

export default class OrganizationRequestService {
  facilityService = new FaciltyService();

  // Validates the owner email by checking if it exists in the user database
  public async validateOwnerEmail(email: string): Promise<boolean> {
    if (!email || !validator.isEmail(email)) {
      return false;
    }

    const user = await User.findOne({
      email: email.toLowerCase().trim(),
    }).collation({ locale: 'en', strength: 2 });
    console.log('User found:', user);

    return !!user;
  }

  // Creates a new organization request with images directly uploaded to Cloudinary
  public async createRequest(
    requesterId: string,
    requestData: CreateRequestDto,
    images?: Express.Multer.File[],
  ): Promise<IOrganizationRequest> {
    // Validate owner email exists in database
    const existingRequest = await OrganizationRequest.findOne({
      organizationName: {
        $regex: new RegExp(`^${requestData.organizationName}$`, 'i'),
      },
    });

    if (existingRequest) {
      throw new ErrorResponse(
        'An organization request with this name already exists',
        400,
      );
    }
    const ownerExists = await this.validateOwnerEmail(requestData.ownerEmail);
    console.log('Owner email exists:', requestData.ownerEmail);
    if (!ownerExists) {
      throw new ErrorResponse(
        'Owner email does not exist in the user database',
        400,
      );
    }

    // Validate facilities
    await this.facilityService.validateFacilities(requestData.facilities);

    // Upload images directly to Cloudinary
    const imageUrls: string[] = [];
    if (images && images.length > 0) {
      const uploadPromises = images.map(image => uploadImage(image));
      const uploadResults = await Promise.all(uploadPromises);
      imageUrls.push(...uploadResults.map(result => result.url));
    }

    // Create request
    const request = await OrganizationRequest.create({
      requesterId,
      status: 'pending',
      ...requestData,
      images: imageUrls, // Store Cloudinary URLs directly
    });

    return request;
  }

  public async getRequestById(
    requestId: string,
  ): Promise<IOrganizationRequest> {
    try {
      // Validate ID format
      const validatedId = validateId(requestId);

      const request = await OrganizationRequest.findById(validatedId)
        .populate('requesterId', 'first_name last_name email')
        .populate('processingAdminId', 'first_name last_name email')
        .populate('organizationId');

      if (!request) {
        throw new ErrorResponse('Organization request not found', 404);
      }

      return request;
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new ErrorResponse('Invalid request ID format', 400);
      }
      throw error;
    }
  }

  public async startProcessing(
    requestId: string,
    adminId: string,
  ): Promise<IOrganizationRequest> {
    try {
      // Validate both IDs
      const validatedRequestId = validateId(requestId);
      const validatedAdminId = validateId(adminId);

      const request = await OrganizationRequest.findById(validatedRequestId);
      if (!request) {
        throw new ErrorResponse('Request not found', 404);
      }

      if (request.status !== 'pending') {
        throw new ErrorResponse(
          `Request cannot be processed. Current status: ${request.status}`,
          400,
        );
      }

      request.status = 'processing';
      request.processingAdminId = new mongoose.Types.ObjectId(validatedAdminId);
      request.processingStartedAt = new Date();
      await request.save();

      return request;
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new ErrorResponse('Invalid ID format', 400);
      }
      throw error;
    }
  }

  // Cancel processing of a request
  public async cancelProcessing(
    requestId: string,
    adminId: string,
  ): Promise<IOrganizationRequest> {
    const request = await OrganizationRequest.findById(requestId);
    if (!request) {
      throw new ErrorResponse('Request not found', 404);
    }

    if (request.status !== 'processing') {
      throw new ErrorResponse('Request is not currently being processed', 400);
    }

    request.status = 'pending';
    request.processingAdminId = undefined;
    request.processingStartedAt = undefined;
    await request.save();

    return request;
  }

  public async approveRequestWithSession(
    requestId: string,
    adminId: string,
    organizationId: string,
    wasEdited: boolean = false,
    adminNotes?: string,
    session?: mongoose.ClientSession,
  ): Promise<ProcessingResult> {
    try {
      // Validate all IDs
      const validatedRequestId = validateId(requestId);

      const validatedOrgId = validateId(organizationId);

      const options = session ? { session } : {};

      const request = await OrganizationRequest.findById(
        validatedRequestId,
      ).session(session || null);
      if (!request) {
        throw new ErrorResponse('Request not found', 404);
      }

      if (request.status !== 'processing') {
        throw new ErrorResponse('Request is not in processing state', 400);
      }

      // Set the status based on whether the data was edited
      request.status = wasEdited ? 'approved_with_changes' : 'approved';

      // Set the organizationId reference
      request.organizationId = new mongoose.Types.ObjectId(validatedOrgId);
      if (adminNotes) request.adminNotes = adminNotes;
      await request.save(options);

      // Notify requester
      
      await this.notifyRequestProcessed(request, true, wasEdited);
      

      return {
        success: true,
        message: wasEdited
          ? 'Organization request approved with changes'
          : 'Organization request approved successfully',
        data: { request },
      };
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new ErrorResponse('Invalid ID format', 400);
      }
      console.error('Error approving request:', error);
      throw new ErrorResponse('Failed to approve organization request', 500);
    }
  }

  /**
   * Determines if organization data differs from the original request
   * @param requestId - ID of the organization request
   * @param orgName - Name of the organization to create
   * @param facilities - Facilities of the organization
   * @param location - Location object of the organization
   * @returns Promise<boolean> - True if data was edited from original request
   */
  public async wasRequestDataEdited(
    requestId: string,
    orgName: string,
    facilities: string[],
    location: any,
    orgContactPhone: string,
    orgContactEmail: string,
  ): Promise<boolean> {
    try {
      // Get the original request
      const request = await this.getRequestById(requestId);
      console.log(request);
      if (!request) {
        throw new ErrorResponse('Organization request not found', 404);
      }

      // Check for differences between request and new organization data
      const nameChanged = request.organizationName !== orgName;
      console.log(
        'requestName:',
        request.organizationName,
        'orgName:',
        orgName,
        'nameChanged:',
        nameChanged,
      );

      // Compare facilities (order might be different so we need to sort)
      const facilitiesChanged =
        facilities.length !== request.facilities.length ||
        !facilities.every(f => request.facilities.includes(f));
      console.log(
        'requestFacilities:',
        request.facilities,
        'newFacilities:',
        facilities,
        'facilitiesChanged:',
        facilitiesChanged,
      );

      // Compare location (check essential fields)
      const locationChanged =
        request.location.place_id !== location.place_id ||
        request.location.address !== location.address ||
        request.location.city !== location.city ||
        request.location.coordinates.coordinates[0] !==
          location.coordinates.coordinates[0] ||
        request.location.coordinates.coordinates[1] !==
          location.coordinates.coordinates[1];
      console.log('locationChanged:', locationChanged, {
        placeId: {
          original: request.location.place_id,
          new: location.place_id,
          changed: request.location.place_id !== location.place_id,
        },
        address: {
          original: request.location.address,
          new: location.address,
          changed: request.location.address !== location.address,
        },
        city: {
          original: request.location.city,
          new: location.city,
          changed: request.location.city !== location.city,
        },
        coordinates: {
          original: request.location.coordinates.coordinates,
          new: location.coordinates.coordinates,
          changed:
            request.location.coordinates.coordinates[0] !==
              location.coordinates.coordinates[0] ||
            request.location.coordinates.coordinates[1] !==
              location.coordinates.coordinates[1],
        },
      });

      const phoneChanged = request.orgContactPhone !== orgContactPhone;
      console.log(
        'requestPhone:',
        request.orgContactPhone,
        'newPhone:',
        orgContactPhone,
        'phoneChanged:',
        phoneChanged,
      );

      const emailChanged = request.orgContactEmail !== orgContactEmail;
      console.log(
        'requestEmail:',
        request.orgContactEmail,
        'newEmail:',
        orgContactEmail,
        'emailChanged:',
        emailChanged,
      );

      console.log('SUMMARY - Changes detected:', {
        nameChanged,
        facilitiesChanged,
        locationChanged,
        phoneChanged,
        emailChanged,
      });

      return (
        nameChanged ||
        facilitiesChanged ||
        locationChanged ||
        phoneChanged ||
        emailChanged
      );
    } catch (error) {
      console.error('Error checking if request was edited:', error);
      throw new ErrorResponse('Failed to compare request data', 500);
    }
  }

  // Notify the requester about the request status
  private async notifyRequestProcessed(
    request: IOrganizationRequest,
    approved: boolean,
    wasEdited: boolean = false,
  ): Promise<void> {
    try {
      const user = await User.findById(request.requesterId);
      if (!user) {
        console.error(`User ${request.requesterId} not found for notification`);
        return;
      }

      const isOwner = user.email === request.ownerEmail;
      const subject = approved
        ? this.getApprovalEmailSubject()
        : this.getRejectionEmailSubject();
      const recipientName = this.getRecipientName(user, isOwner);

      // Build text message for fallback
      const textMessage = this.buildMainMessage(
        recipientName,
        request,
        approved,
        wasEdited,
        isOwner,
      );

      // Build HTML message
      const htmlContent = this.buildHtmlMessage(
        recipientName,
        request,
        approved,
        wasEdited,
        isOwner,
      );

      // Handle owner notifications
      await this.handleOwnerNotifications(
        user,
        request,
        subject,
        textMessage,
        htmlContent,
        approved,
        wasEdited,
        isOwner,
      );
    } catch (error) {
      console.error('Failed to send notification email:', error);
    }
  }

  // Helper functions

  private getApprovalEmailSubject(): string {
    return 'Organization Request Approved - TurfMania';
  }

  private getRejectionEmailSubject(): string {
    return 'Organization Request Rejected - TurfMania';
  }

  private getRecipientName(user: any, isOwner: boolean): string {
    return `${user.first_name || ''} ${user.last_name || ''}`.trim() || (isOwner ? 'Owner' : 'Valued Customer');
  }

  private buildMainMessage(
    recipientName: string,
    request: IOrganizationRequest,
    approved: boolean,
    wasEdited: boolean,
    isOwner: boolean,
  ): string {
    let message = `Dear ${recipientName},\n\n`;

    if (approved) {
      message += this.buildApprovalMessage(request, wasEdited, isOwner);
    } else {
      message += this.buildRejectionMessage(request);
    }

    message += this.getCommonFooter();
    return message;
  }

  private buildHtmlMessage(
    recipientName: string,
    request: IOrganizationRequest,
    approved: boolean,
    wasEdited: boolean,
    isOwner: boolean,
  ): string {
    const headerColor = approved ? '#4a9d61' : '#d32f2f';
    const headerText = approved 
      ? wasEdited 
        ? 'Organization Request Approved with Changes'
        : 'Organization Request Approved'
      : 'Organization Request Rejected';

    let htmlContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eaeaea; border-radius: 5px; background-color: #f9f9f9;">
        <h2 style="color: ${headerColor}; text-align: center; margin-bottom: 20px;">${headerText}</h2>
        
        <div style="background-color: #ffffff; border: 1px solid #eaeaea; border-radius: 3px; padding: 15px; margin-bottom: 20px;">
          <h3 style="color: #333; margin-top: 0;">Dear ${recipientName},</h3>
    `;

    if (approved) {
      htmlContent += this.buildHtmlApprovalContent(request, wasEdited, isOwner);
    } else {
      htmlContent += this.buildHtmlRejectionContent(request);
    }

    htmlContent += this.getHtmlCommonFooter();
    return htmlContent;
  }

  private buildHtmlApprovalContent(
    request: IOrganizationRequest,
    wasEdited: boolean,
    isOwner: boolean,
  ): string {
    const orgName = request.organizationName;
    
    let content = `
      <p style="font-size: 16px; line-height: 1.6; margin-bottom: 20px;">
        We are pleased to inform you that your request to create organization 
        <strong>"${orgName}"</strong> has been approved${wasEdited ? ' with some changes' : ''}.
      </p>
      
      <div style="background-color: #eafbf0; border-left: 4px solid #4a9d61; padding: 15px; margin: 20px 0;">
        <p style="font-size: 15px; margin: 0;">
          The organization has been successfully created in our system and is now active.
          Visit ${process.env.ORGANIZATION_URL} to get access to your organization dashboard.
          ${request.organizationId 
            ? `<br><br><strong>Organization ID:</strong> ${request.organizationId}`
            : ''
          }
        </p>
      </div>
    `;

    if (wasEdited) {
      content += `
        <div style="background-color: #fff8e1; border-left: 4px solid #ffa726; padding: 15px; margin: 20px 0;">
          <p style="font-size: 15px; margin: 0;">
            <strong>Please Note:</strong> Some details of your request were modified during the approval process.
            You can view the final organization details in your dashboard.
          </p>
        </div>
      `;
    }

    if (isOwner) {
      content += `
        <p style="font-size: 16px; line-height: 1.6;">
          As the owner of <strong>"${orgName}"</strong>, you now have full administrative access to manage the organization.
        </p>
        
        <div style="text-align: center; margin-top: 25px;">
          <a href="${process.env.ORGANIZATION_URL}" 
             style="background-color: #4a9d61; color: white; padding: 12px 24px; text-decoration: none; 
                    border-radius: 4px; font-weight: bold; display: inline-block;">
            Go to Organization Dashboard
          </a>
        </div>
      `;
    }

    return content;
  }

  private buildHtmlRejectionContent(request: IOrganizationRequest): string {
    let content = `
      <p style="font-size: 16px; line-height: 1.6; margin-bottom: 20px;">
        We regret to inform you that your request to create organization 
        <strong>"${request.organizationName}"</strong> has been rejected.
      </p>
    `;

    if (request.adminNotes) {
      content += `
        <div style="background-color: #ffebee; border-left: 4px solid #d32f2f; padding: 15px; margin: 20px 0;">
          <h4 style="color: #d32f2f; margin-top: 0; margin-bottom: 10px;">Reason for Rejection</h4>
          <p style="font-size: 15px; margin: 0;">${request.adminNotes}</p>
        </div>
        
        <p style="font-size: 16px; line-height: 1.6;">
          You may submit a new request after addressing the issues mentioned above.
        </p>
      `;
    }

    content += `
      <div style="text-align: center; margin-top: 25px;">
        <a href="${process.env.CLIENT_URL}/organization-request" 
           style="background-color: #2196f3; color: white; padding: 12px 24px; text-decoration: none; 
                  border-radius: 4px; font-weight: bold; display: inline-block;">
          Submit New Request
        </a>
      </div>
    `;

    return content;
  }

  private buildApprovalMessage(
    request: IOrganizationRequest,
    wasEdited: boolean,
    isOwner: boolean,
  ): string {
    let message =
      `We are pleased to inform you that your request to create organization "${
        request.organizationName
      }" has been approved${wasEdited ? ' with some changes' : ''}.\n\n` +
      `The organization has been successfully created in our system and is now active.\n` +
      (request.organizationId
        ? `Organization ID: ${request.organizationId}\n\n`
        : '\n');

    if (wasEdited) {
      message += `Please note that some details of your request were modified during the approval process. You can view the final organization details in your dashboard.\n\n`;
    }

    if (isOwner) {
      message += `As the owner of "${request.organizationName}", you now have full administrative access to manage the organization.\n\n`;
    }

    return message;
  }

  private buildRejectionMessage(request: IOrganizationRequest): string {
    let message = `We regret to inform you that your request to create organization "${request.organizationName}" has been rejected.\n\n`;

    if (request.adminNotes) {
      message +=
        `Reason: ${request.adminNotes}\n\n` +
        `You may submit a new request after addressing the issues mentioned above.\n\n`;
    }

    return message;
  }

  private getCommonFooter(): string {
    return (
      `If you have any questions or need further assistance, please don't hesitate to contact our support team at supportMail@gmail.com.\n\n` +
      `Thank you for choosing TurfMania!\n\n` +
      `Best regards,\n` +
      `The TurfMania Team\n\n` +
      `[This is an automated message. Please do not reply directly to this email.]`
    );
  }

  private getHtmlCommonFooter(): string {
    return `
        </div>
        
        <p style="font-size: 15px; line-height: 1.6; color: #555; margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee;">
          If you have any questions or need further assistance, please don't hesitate to contact our support team at
          <a href="mailto:supportMail@gmail.com" style="color: #4a9d61; text-decoration: none;">supportMail@gmail.com</a>.
        </p>
        
        <p style="font-size: 15px; line-height: 1.6; color: #555;">
          Thank you for choosing TurfMania!
        </p>
        
        <p style="font-size: 15px; line-height: 1.6; color: #555;">
          Best regards,<br>
          The TurfMania Team
        </p>
        
        <p style="font-size: 12px; color: #999; font-style: italic; margin-top: 20px; text-align: center;">
          This is an automated message. Please do not reply directly to this email.
        </p>
      </div>
    `;
  }

  private async handleOwnerNotifications(
    user: any,
    request: IOrganizationRequest,
    subject: string,
    textMessage: string,
    htmlContent: string,
    approved: boolean,
    wasEdited: boolean,
    isOwner: boolean,
  ): Promise<void> {
    if (isOwner) {
      // Send owner-specific message
      await sendEmail(user.email, subject, textMessage, htmlContent);
    } else {
      // Send standard message to requester
      await sendEmail(user.email, subject, textMessage, htmlContent);

      // Send owner-specific message to owner (if different)
      const ownerTextMessage = this.buildOwnerMessage(
        request,
        textMessage,
        approved,
        wasEdited,
      );
      
      const ownerHtmlContent = this.buildOwnerHtmlMessage(
        request,
        approved,
        wasEdited
      );
      
      await sendEmail(request.ownerEmail, subject, ownerTextMessage, ownerHtmlContent);
    }
  }

  private buildOwnerMessage(
    request: IOrganizationRequest,
    baseMessage: string,
    approved: boolean,
    wasEdited: boolean,
  ): string {
    let statusText: string;
    if (approved) {
      statusText = wasEdited ? 'approved with some modifications' : 'approved';
    } else {
      statusText = 'rejected';
    }

    return (
      `Dear ${request.ownerEmail.split('@')[0]},\n\n` +
      `You had been designated as the owner of organization "${request.organizationName}" which was just ${statusText} on TurfMania.\n\n` +
      (approved
        ? `As the owner, you have full administrative access to manage the organization.\n\n`
        : '') +
      baseMessage.substring(
        baseMessage.indexOf('\n\nIf you have any questions'),
      )
    );
  }
  
  private buildOwnerHtmlMessage(
    request: IOrganizationRequest,
    approved: boolean,
    wasEdited: boolean,
  ): string {
    const headerColor = approved ? '#4a9d61' : '#d32f2f';
    const headerText = approved 
      ? wasEdited 
        ? 'Organization Request Approved with Changes'
        : 'Organization Request Approved'
      : 'Organization Request Rejected';
    
    let statusText: string;
    if (approved) {
      statusText = wasEdited ? 'approved with some modifications' : 'approved';
    } else {
      statusText = 'rejected';
    }
    
    const ownerName = request.ownerEmail.split('@')[0];
    
    let htmlContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eaeaea; border-radius: 5px; background-color: #f9f9f9;">
        <h2 style="color: ${headerColor}; text-align: center; margin-bottom: 20px;">${headerText}</h2>
        
        <div style="background-color: #ffffff; border: 1px solid #eaeaea; border-radius: 3px; padding: 15px; margin-bottom: 20px;">
          <h3 style="color: #333; margin-top: 0;">Dear ${ownerName},</h3>
          
          <p style="font-size: 16px; line-height: 1.6; margin-bottom: 20px;">
            You had been designated as the owner of organization 
            <strong>"${request.organizationName}"</strong> which was just ${statusText} on TurfMania.
          </p>
    `;
    
    if (approved) {
      htmlContent += `
        <div style="background-color: #eafbf0; border-left: 4px solid #4a9d61; padding: 15px; margin: 20px 0;">
          <p style="font-size: 15px; margin: 0;">
            As the owner, you have full administrative access to manage the organization.
          </p>
        </div>
        
        <div style="text-align: center; margin-top: 25px;">
          <a href="${process.env.ORGANIZATION_URL}" 
             style="background-color: #4a9d61; color: white; padding: 12px 24px; text-decoration: none; 
                    border-radius: 4px; font-weight: bold; display: inline-block;">
            Go to Organization Dashboard
          </a>
        </div>
      `;
    }
    
    htmlContent += this.getHtmlCommonFooter();
    return htmlContent;
  }

  // Reject request and notify requester
  public async rejectRequest(
    requestId: string,
    adminId: string,
    rejectionNotes: string,
  ): Promise<IOrganizationRequest> {
    const request = await OrganizationRequest.findById(requestId);
    if (!request) {
      throw new ErrorResponse('Request not found', 404);
    }

    if (request.status !== 'processing' && request.status !== 'pending') {
      throw new ErrorResponse(
        'Request cannot be rejected in its current state',
        400,
      );
    }

    request.status = 'rejected';
    request.adminNotes = rejectionNotes;
    await request.save();

    // Notify requester
    await this.notifyRequestProcessed(request, false);

    return request;
  }

  public async getUserOrganizationRequests(
    userId: string,
  ): Promise<IOrganizationRequest[]> {
    try {
      const validatedUserId = validateId(userId);

      return OrganizationRequest.find({ requesterId: validatedUserId })
        .sort({ createdAt: -1 })
        .select('-processingAdminId -__v')
        .lean();
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new ErrorResponse('Invalid user ID format', 400);
      }
      throw error;
    }
  }

  public async getRequests(
    filters: RequestFilters = {},
    pagination: PaginationOptions = { page: 1, limit: 10 },
  ): Promise<RequestsResult> {
    const {
      status,
      fromDate,
      toDate,
      requesterEmail,
      ownerEmail,
      sortBy = 'createdAt',
      sortOrder = 'desc',
    } = filters;
    const { page, limit } = pagination;
    const query: any = {};

    // Apply status filter
    if (status) {
      query.status = Array.isArray(status) ? { $in: status } : status;
    }

    // Apply date range filter
    if (fromDate || toDate) {
      query.createdAt = {};
      if (fromDate) query.createdAt.$gte = fromDate;
      if (toDate) query.createdAt.$lte = toDate;
    }

    // Apply requester email filter if specified
    if (requesterEmail) {
      // Find the user IDs for the specified requester email
      const requesters = await User.find({
        email: { $regex: new RegExp(requesterEmail, 'i') },
      }).select('_id');

      if (requesters.length > 0) {
        const requesterIds = requesters.map(requester => requester._id);
        query.requesterId = { $in: requesterIds };
      } else {
        // If no match, return empty result
        return {
          total: 0,
          page,
          pages: 0,
          requests: [],
        };
      }
    }

    // Apply owner email filter if specified
    if (ownerEmail) {
      query.ownerEmail = { $regex: new RegExp(ownerEmail, 'i') };
    }

    // Count total before applying pagination
    const total = await OrganizationRequest.countDocuments(query);
    const pages = Math.ceil(total / limit);
    const skip = (page - 1) * limit;

    // Build sort object
    const sortOptions: any = {};
    sortOptions[sortBy] = sortOrder === 'asc' ? 1 : -1;

    // Fetch paginated results with sorting
    const requests = await OrganizationRequest.find(query)
      .sort(sortOptions)
      .skip(skip)
      .limit(limit)
      .populate('requesterId', 'first_name last_name email')
      .populate('processingAdminId', 'first_name last_name email');

    return {
      total,
      page,
      pages,
      requests,
    };
  }

  public async resetStuckProcessingRequests(
    timeoutHours: number = 2,
  ): Promise<number> {
    const cutoffTime = new Date();
    cutoffTime.setHours(cutoffTime.getHours() - timeoutHours);

    const result = await OrganizationRequest.updateMany(
      {
        status: 'processing',
        processingStartedAt: { $lt: cutoffTime },
      },
      {
        $set: { status: 'pending' },
        $unset: { processingAdminId: '', processingStartedAt: '' },
      },
    );

    return result.modifiedCount;
  }

  public startPeriodicCleanup(
    timeoutHours: number = 2,
    intervalHours: number = 1,
  ): void {
    const intervalMs = intervalHours * 60 * 60 * 1000;

    setInterval(async () => {
      try {
        const count = await this.resetStuckProcessingRequests(timeoutHours);
        if (count > 0) {
          console.log(`Reset ${count} stuck processing organization requests`);
        }
      } catch (error) {
        console.error('Error resetting stuck organization requests:', error);
      }
    }, intervalMs);
  }
}
