// organization-request.controller.ts (Updated)
import { NextFunction, Request, Response } from "express";
import validator from "validator";
import asyncHandler from "../../shared/middleware/async";
import ErrorResponse from "../../utils/errorResponse";
import { AuthRequest } from "../auth/auth.middleware";
import OrganizationRequestService,{ RequestFilters, PaginationOptions } from "./organization-request.service";
import { RequestStatus } from "./organization-request.model";


export default class OrganizationRequestController {
  private readonly organizationRequestService: OrganizationRequestService;

  constructor() {
    this.organizationRequestService = new OrganizationRequestService();
  }

  /**
   * @route   POST /api/v1/organization-requests
   * @desc    Create a new organization request
   * @access  Private
   */
  public createOrganizationRequest = asyncHandler(
    async (req: AuthRequest, res: Response, next: NextFunction) => {
      if (!req.user) {
        throw new ErrorResponse("User not authenticated", 401);
      }

      // Basic validation
      const {
        organizationName,
        facilities,
        location,
        contactPhone,
        ownerEmail,
        orgContactPhone,
        orgContactEmail,
        requestNotes,
      } = req.body;
      console.log("Request body:", req.body);
        
      // Validate required fields
      if (
        !organizationName ||
        !facilities ||
        !location ||
        !contactPhone ||
        !ownerEmail ||
        !orgContactPhone ||
        !orgContactEmail 
      ) {
        throw new ErrorResponse("Missing required fields", 400);
      }

      // Sanitize and validate email field
      const sanitizedOwnerEmail = validator
        .trim(ownerEmail ?? "")
        .toLowerCase();

      // Validate email format
      if (!validator.isEmail(sanitizedOwnerEmail)) {
        throw new ErrorResponse("Invalid owner email format", 400);
      }

      // Validate organization contact email
      const sanitizedOrgContactEmail = validator
        .trim(orgContactEmail ?? "")
        .toLowerCase();

      if (!validator.isEmail(sanitizedOrgContactEmail)) {
        throw new ErrorResponse("Invalid organization contact email format", 400);
      }

      // Process facilities if it's a string
      let parsedFacilities: string[];
      
        parsedFacilities =
          typeof facilities === "string" ? JSON.parse(facilities) : facilities;
        if (!Array.isArray(parsedFacilities) || parsedFacilities.length === 0) {
          throw new ErrorResponse("Facilities must be a non-empty array", 400);
        }
      

      // Process location if it's a string
      let parsedLocation: any;
     
        parsedLocation =
          typeof location === "string" ? JSON.parse(location) : location;

        // Validate required location fields
        if (
          !parsedLocation.place_id ||
          !parsedLocation.address ||
          !parsedLocation.coordinates ||
          !parsedLocation.city
        ) {
          throw new ErrorResponse("Location missing required fields", 400);
        }
     

      // Handle file uploads
      const images = (req.files as Express.Multer.File[]) || [];

      const request = await this.organizationRequestService.createRequest(
        req.user.id,
        {
          organizationName: validator.trim(organizationName),
          facilities: parsedFacilities,
          location: parsedLocation,
          contactPhone: validator.trim(contactPhone),
          ownerEmail: sanitizedOwnerEmail,
          requestNotes: requestNotes ? validator.trim(requestNotes) : undefined,
          orgContactPhone: validator.trim(orgContactPhone),
          orgContactEmail: sanitizedOrgContactEmail,
        },
        images
      );

      res.status(201).json({
        success: true,
        data: request,
        message: "Organization request submitted successfully",
      });
    }
  );

 

  /**
   * @route   PUT /api/v1/organization-requests/:id/process
   * @desc    Start processing an organization request
   * @access  Private (Admin only)
   */
  public startProcessingRequest = asyncHandler(
    async (req: AuthRequest, res: Response) => {
      if (!req.user) {
        throw new ErrorResponse("User not authenticated", 401);
      }

      const { id } = req.params;
      const request = await this.organizationRequestService.startProcessing(
        id,
        req.user.id
      );

      res.status(200).json({
        success: true,
        data: request,
        message: "Request processing started",
      });
    }
  );

  /**
   * @route   PUT /api/v1/organization-requests/:id/cancel-processing
   * @desc    Cancel processing an organization request
   * @access  Private (Admin only)
   */
  public cancelProcessingRequest = asyncHandler(
    async (req: AuthRequest, res: Response) => {
      if (!req.user) {
        throw new ErrorResponse("User not authenticated", 401);
      }

      const { id } = req.params;
      const request = await this.organizationRequestService.cancelProcessing(
        id,
        req.user.id
      );

      res.status(200).json({
        success: true,
        data: request,
        message: "Request processing cancelled",
      });
    }
  );

  /**
   * @route   PUT /api/v1/organization-requests/:id/reject
   * @desc    Reject an organization request
   * @access  Private (Admin only)
   */
  public rejectOrganizationRequest = asyncHandler(
    async (req: AuthRequest, res: Response) => {
      if (!req.user) {
        throw new ErrorResponse("User not authenticated", 401);
      }

      const { id } = req.params;
      const { adminNotes } = req.body;

      if (!adminNotes) {
        throw new ErrorResponse("Rejection reason is required", 400);
      }

      const request = await this.organizationRequestService.rejectRequest(
        id,
        req.user.id,
        validator.trim(adminNotes)
      );

      res.status(200).json({
        success: true,
        data: request,
        message: "Organization request rejected",
      });
    }
  );

  /**
   * @route   GET /api/v1/organization-requests/my/:id
   * @desc    Get requester's own organization request by ID
   * @access  Private (Requester only)
   */
  public getOrganizationRequestAsUser = asyncHandler(
    async (req: AuthRequest, res: Response) => {
      if (!req.user) {
        throw new ErrorResponse("User not authenticated", 401);
      }

      const { id } = req.params;
      const request = await this.organizationRequestService.getRequestById(id);

      if (!request.requesterId.equals(req.user.id)) {
        throw new ErrorResponse("Not authorized to view this request", 403);
      }

      res.status(200).json({
        success: true,
        data: request,
      });
    }
  );

  /**
   * @route   GET /api/v1/organization-requests/admin/:id
   * @desc    Get any organization request (admin access)
   * @access  Private (Admin only)
   */
  public getOrganizationRequestAsAdmin = asyncHandler(
    async (req: AuthRequest, res: Response) => {
      if (!req.user) {
        throw new ErrorResponse("User not authenticated", 401);
      }

      const { id } = req.params;
      const request = await this.organizationRequestService.getRequestById(id);

      res.status(200).json({
        success: true,
        data: request,
      });
    }
  );

  /**
   * @route   GET /api/v1/organization-requests/user
   * @desc    Get organization requests for current user
   * @access  Private
   */
  public getUserOrganizationRequests = asyncHandler(
    async (req: AuthRequest, res: Response) => {
      if (!req.user) {
        throw new ErrorResponse("User not authenticated", 401);
      }

      const requests =
        await this.organizationRequestService.getUserOrganizationRequests(
          req.user.id
        );

      res.status(200).json({
        success: true,
        data: requests,
      });
    }
  );

  /**
   * Extract filter options from request query parameters
   * @private
   */
  private extractRequestFilters(req: Request): RequestFilters {
    const status = req.query.status as string;
    const fromDate = req.query.fromDate
      ? new Date(req.query.fromDate as string)
      : undefined;
    const toDate = req.query.toDate
      ? new Date(req.query.toDate as string)
      : undefined;
    const requesterEmail = req.query.requesterEmail as string;
    const ownerEmail = req.query.ownerEmail as string;
    const sortBy = req.query.sortBy as
      | "createdAt"
      | "updatedAt"
      | "organizationName";
    const sortOrder = req.query.sortOrder as "asc" | "desc";

    const filters: RequestFilters = {};

    // Add status filter
    if (status) {
      filters.status = status.includes(",")
        ? (status.split(",") as RequestStatus[])
        : (status as RequestStatus);
    }

    // Add date filters
    if (fromDate) filters.fromDate = fromDate;
    if (toDate) filters.toDate = toDate;

    // Add email filters
    if (requesterEmail) filters.requesterEmail = requesterEmail;
    if (ownerEmail) filters.ownerEmail = ownerEmail;

    // Add sorting options
    if (
      sortBy &&
      ["createdAt", "updatedAt", "organizationName"].includes(sortBy)
    ) {
      filters.sortBy = sortBy;
    }

    if (sortOrder && ["asc", "desc"].includes(sortOrder)) {
      filters.sortOrder = sortOrder;
    }

    return filters;
  }

  /**
   * Extract pagination options from request query parameters
   * @private
   */
  private extractPaginationOptions(req: Request): PaginationOptions {
    const page = Math.max(1, parseInt(req.query.page as string) || 1);
    const limit = Math.min(
      50,
      Math.max(1, parseInt(req.query.limit as string) || 10)
    );
    return { page, limit };
  }

  /**
   * @route   GET /api/v1/organization-requests
   * @desc    Get all organization requests with filtering and pagination
   * @access  Private (Admin only)
   */
  public getOrganizationRequests = asyncHandler(
    async (req: Request, res: Response) => {
      const filters = this.extractRequestFilters(req);
      const pagination = this.extractPaginationOptions(req);

      const results = await this.organizationRequestService.getRequests(
        filters,
        pagination
      );

      res.status(200).json({
        success: true,
        data: results,
        meta: {
          total: results.total,
          page: results.page,
          pages: results.pages,
          filters: filters,
        },
      });
    }
  );
}
