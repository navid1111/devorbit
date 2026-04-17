import { NextFunction, Request, Response } from 'express';
import mongoose from 'mongoose';
import validator from 'validator';
import asyncHandler from '../../shared/middleware/async';
import ErrorResponse from '../../utils/errorResponse';
import { AuthRequest } from '../auth/auth.middleware';
import { IOrganization } from './organization.model';
import { organizationService } from './organization.service';

interface CreateOrganizationBody {
  name: string;
  facilities: string[];
  requestId?: string;
  wasEdited?: boolean;
  orgContactPhone: string;
  orgContactEmail: string;
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
}

interface AssignOwnerBody {
  userId: string;
}
// Interface for Update Organization Body
interface UpdateOrganizationBody
  extends Omit<Partial<CreateOrganizationBody>, 'facilities'> {
  facilities?: string | string[];
  imagesToKeep?: string[];
  orgContactPhone?: string;
  orgContactEmail?: string;
}

// Interface for Create Role Body
interface CreateRoleBody {
  roleName: string;
  permissions: string[]; // Array of permission names
}

// Interface for Assign Role Body
interface AssignRoleBody {
  roleId: string;
}

/**
 * @route   POST /api/v1/organizations
 * @desc    Create a new organization
 * @access  Private (Admin only)
 */
export const createOrganization = asyncHandler(
  async (
    req: AuthRequest & {
      body: CreateOrganizationBody & {
        requestId?: string;
        adminNotes?: string;
      };
    },
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const userId = ensureAuthenticated(req.user);
      const {
        name,
        facilities,
        location: rawLocation,
        orgContactEmail,
        orgContactPhone,
        requestId,
        adminNotes,
      } = ensureRequiredFields(req.body);

      const sanitizedName = name;
      const parsedFacilities = parseAndValidateFacilities(facilities);
      const parsedLocation = parseAndValidateLocation(rawLocation);

      validateContactInfo(orgContactEmail, orgContactPhone);

      const images = req.files as Express.Multer.File[];

      const organization = await organizationService.createOrganization({
        name: sanitizedName,
        facilities: parsedFacilities,
        location: parsedLocation,
        orgContact: {
          phone: orgContactPhone,
          email: orgContactEmail,
        },
        images,
        requestId,
        adminId: userId,
        adminNotes,
      });

      if (!organization) {
        throw new ErrorResponse('Failed to create organization', 500);
      }

      return sendSuccessResponse(res, organization, requestId);
    } catch (err) {
      return next(err);
    }
  },
);

/** Helper Functions */
function ensureAuthenticated(user: { id: string } | undefined): string {
  if (!user) {
    throw new ErrorResponse('User not authenticated', 401);
  }
  return user.id;
}

function ensureRequiredFields(body: any) {
  const {
    name,
    facilities,
    location,
    orgContactEmail,
    orgContactPhone,
    requestId,
    adminNotes,
  } = body;

  if (!name) throw new ErrorResponse('Name is required', 400);
  if (!facilities) throw new ErrorResponse('Facilities are required', 400);
  if (!orgContactEmail)
    throw new ErrorResponse('Contact email is required', 400);
  if (!orgContactPhone)
    throw new ErrorResponse('Contact phone is required', 400);

  return {
    name,
    facilities,
    location,
    orgContactEmail,
    orgContactPhone,
    requestId,
    adminNotes,
  };
}

function sanitizeName(name: string): string {
  return name.charAt(0).toUpperCase() + name.slice(1).toLowerCase();
}

function parseAndValidateFacilities(facilities: string | any[]): string[] {
  let parsedFacilities: string[];

  try {
    parsedFacilities =
      typeof facilities === 'string' ? JSON.parse(facilities) : facilities;

    if (!Array.isArray(parsedFacilities)) {
      throw new ErrorResponse('Facilities must be an array', 400);
    }

    if (parsedFacilities.length === 0) {
      throw new ErrorResponse('At least one facility is required', 400);
    }

    if (!parsedFacilities.every(facility => typeof facility === 'string')) {
      throw new ErrorResponse('All facilities must be strings', 400);
    }

    return parsedFacilities.map(
      facility =>
        facility.charAt(0).toUpperCase() + facility.slice(1).toLowerCase(),
    );
  } catch (error) {
    if (error instanceof ErrorResponse) throw error;
    throw new ErrorResponse(
      `Invalid facilities format: ${(error as Error).message}`,
      400,
    );
  }
}

function parseAndValidateLocation(location: any): IOrganization['location'] {
  try {
    const parsedLocation =
      typeof location === 'string' ? JSON.parse(location) : location;

    if (!parsedLocation) {
      throw new ErrorResponse('Location is required', 400);
    }

    const requiredFields = ['place_id', 'address', 'coordinates', 'city'];
    const missingFields = requiredFields.filter(
      field => !parsedLocation[field],
    );

    if (missingFields.length > 0) {
      throw new ErrorResponse(
        `Missing required location fields: ${missingFields.join(', ')}`,
        400,
      );
    }

    if (
      !parsedLocation.coordinates.type ||
      !parsedLocation.coordinates.coordinates
    ) {
      throw new ErrorResponse('Invalid coordinates format', 400);
    }

    return parsedLocation;
  } catch (error) {
    if (error instanceof ErrorResponse) throw error;
    throw new ErrorResponse(
      `Invalid location format: ${(error as Error).message}`,
      400,
    );
  }
}

function validateContactInfo(email: string, phone: string): void {
  if (!validator.isEmail(email)) {
    throw new ErrorResponse('Invalid contact email format', 400);
  }

  // Phone validation can be expanded here if needed
}

function sendSuccessResponse(
  res: Response,
  organization: IOrganization | null,
  requestId?: string,
): Response {
  if (!organization) {
    throw new ErrorResponse('Failed to create organization', 500);
  }

  const message = requestId
    ? 'Organization created and request approved successfully'
    : 'Organization created successfully';

  return res.status(201).json({
    success: true,
    data: organization,
    message,
  });
}

/**
 * @route   POST /api/v1/organizations/:id/assign-owner
 * @desc    Assign a user as the owner of an organization
 * @access  Private (Requires 'assign_organization_owner' permission)
 */
export const assignOwner = asyncHandler(
  async (
    req: AuthRequest & { params: { id: string }; body: AssignOwnerBody },
    res: Response,
    next: NextFunction,
  ) => {
    const { id: organizationId } = req.params;
    const { userId } = req.body;

    // Validate required fields
    if (!userId) {
      return next(new ErrorResponse('User ID is required', 400));
    }

    // Validate MongoDB IDs
    if (!mongoose.Types.ObjectId.isValid(organizationId)) {
      return next(new ErrorResponse('Invalid Organization ID', 400));
    }

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return next(new ErrorResponse('Invalid User ID', 400));
    }

    const updatedOrganization =
      await organizationService.assignOwnerToOrganization(
        organizationId,
        userId,
      );

    res.status(200).json({
      success: true,
      data: updatedOrganization,
      message: `User ${userId} assigned as owner successfully`,
    });
  },
);

/**
 * @route   PUT /api/v1/organizations/:id
 * @desc    Update an organization
 * @access  Private (Admin only)
 */
export const updateOrganization = asyncHandler(
  async (
    req: AuthRequest & { params: { id: string }; body: UpdateOrganizationBody },
    res: Response,
    next: NextFunction,
  ) => {
    const { id } = req.params;
    const { name, facilities, location, ...rest } = req.body;

    const newImages = req.files as Express.Multer.File[];

    const updateData: Partial<IOrganization> = {};

    // Sanitize and add name if provided
    if (name) {
      updateData.name =
        name.charAt(0).toUpperCase() + name.slice(1).toLowerCase();
    }

    // Sanitize and add facilities if provided
    if (facilities) {
      let parsedFacilities =
        typeof facilities === 'string' ? JSON.parse(facilities) : facilities;

      // Validate array elements are strings
      if (
        !Array.isArray(parsedFacilities) ||
        !parsedFacilities.every(facility => typeof facility === 'string')
      ) {
        return next(
          new ErrorResponse('Facilities must be an array of strings', 400),
        );
      }

      // Sanitize facility names
      updateData.facilities = parsedFacilities.map(
        facility =>
          facility.charAt(0).toUpperCase() + facility.slice(1).toLowerCase(),
      );
    }

    if (location) {
      updateData.location =
        typeof location === 'string' ? JSON.parse(location) : location;
    }

    Object.assign(updateData, rest);

    const organization = await organizationService.updateOrganization(
      id,
      updateData,
      newImages,
    );

    if (!organization) {
      return next(new ErrorResponse('Organization not found', 404));
    }

    res.status(200).json({
      success: true,
      data: organization,
      message: 'Organization updated successfully',
    });
  },
);

/**
 * @route   DELETE /api/v1/organizations/:id
 * @desc    Delete an organization
 * @access  Private (Admin only)
 */
export const deleteOrganization = asyncHandler(
  async (req: Request<{ id: string }>, res: Response, next: NextFunction) => {
    const { id } = req.params;

    const result = await organizationService.deleteOrganization(id);

    if (result.deletedCount === 0) {
      return next(new ErrorResponse('Organization not found', 404));
    }

    res.status(200).json({
      success: true,
      message: 'Organization deleted successfully',
    });
  },
);

/**
 * @route   POST /api/v1/organizations/:id/roles
 * @desc    Create a new role within an organization
 * @access  Private (Requires 'manage_organization_roles' permission for this organization)
 */
export const createOrganizationRole = asyncHandler(
  async (
    req: AuthRequest & { params: { id: string }; body: CreateRoleBody },
    res: Response,
    next: NextFunction,
  ) => {
    const { id: organizationId } = req.params;
    const { roleName, permissions } = req.body;

    // Validate required fields
    if (!roleName || !permissions) {
      return next(
        new ErrorResponse('Role name and permissions are required', 400),
      );
    }

    // Validate permissions array
    if (!Array.isArray(permissions) || permissions.length === 0) {
      return next(
        new ErrorResponse('Permissions must be a non-empty array', 400),
      );
    }

    // Validate Organization ID
    if (!mongoose.Types.ObjectId.isValid(organizationId)) {
      return next(new ErrorResponse('Invalid Organization ID', 400));
    }

    const newRole = await organizationService.createOrganizationRole(
      organizationId,
      roleName,
      permissions,
    );

    res.status(201).json({
      success: true,
      data: newRole,
      message: `Role '${roleName}' created successfully for organization ${organizationId}`,
    });
  },
);

/**
 * @route   GET /api/organizations/:organizationId/other-turfs/:turfId
 * @desc    Fetch other turfs from the same organization excluding the current turf
 * @access  Public
 */
export const fetchOtherTurfs = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    const { organizationId, turfId } = req.params;
    const turfs = await organizationService.getOtherTurfsByOrganization(
      organizationId,
      turfId,
    );
    res.status(200).json({ success: true, data: turfs });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   GET /api/v1/organizations/:id
 * @desc    Get organization by ID
 * @access  Public
 */
export const getOrganization = asyncHandler(
  async (req: Request<{ id: string }>, res: Response, next: NextFunction) => {
    const { id } = req.params;

    const organization = await organizationService.getOrganizationById(id);

    res.status(200).json({
      success: true,
      data: organization,
    });
  },
);

/**
 * @route   GET /api/v1/organizations/:orgId/roles
 * @desc    Get all roles for a specific organization
 * @access  Private (Requires organization access)
 */
export const getOrganizationRoles = asyncHandler(
  async (
    req: AuthRequest & { params: { orgId: string } },
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const { orgId } = req.params;
      const roles = await organizationService.getOrganizationRoles(orgId);
      res.status(200).json({ success: true, data: roles });
    } catch (err) {
      next(err);
    }
  },
);

export const getOrganizationRoleMembers = asyncHandler(
  async (
    req: AuthRequest & { params: { orgId: string } },
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const { orgId } = req.params;
      const members = await organizationService.getOrganizationRoleMembers(
        orgId,
      );
      res.status(200).json({ success: true, data: members });
    } catch (err) {
      next(err);
    }
  },
);

export const getOrganizationUnassignedUsers = asyncHandler(
  async (
    req: AuthRequest & { params: { orgId: string } },
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const { orgId } = req.params;
      const users = await organizationService.getOrganizationUnassignedUsers(
        orgId,
      );
      res.status(200).json({ success: true, data: users });
    } catch (err) {
      next(err);
    }
  },
);

export const updateOrganizationRolePermissions = asyncHandler(
  async (
    req: AuthRequest & {
      params: { orgId: string; roleId: string };
      body: { permissions: string[] };
    },
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const { orgId, roleId } = req.params;
      const { permissions } = req.body;
      const updatedRole =
        await organizationService.updateOrganizationRolePermissions(
          orgId,
          roleId,
          permissions,
        );
      res.status(200).json({ success: true, data: updatedRole });
    } catch (err) {
      next(err);
    }
  },
);

/**
 * @route   POST /api/v1/organizations/:orgId/users/:userId/roles/:roleId
 * @desc    Assign a user to a role within an organization
 * @access  Private (Requires manage_organization_roles permission)
 */
export const assignUserToOrganizationRole = asyncHandler(
  async (
    req: AuthRequest & {
      params: { orgId: string; userId: string; roleId: string };
    },
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const { orgId, userId, roleId } = req.params;
      const roleAssignment =
        await organizationService.assignUserToOrganizationRole(
          orgId,
          userId,
          roleId,
        );
      res.status(200).json({ success: true, data: roleAssignment });
    } catch (err) {
      next(err);
    }
  },
);

/**
 * @route   GET /api/v1/organizations/:orgId/roles/:roleId/permissions
 * @desc    Get all permissions associated with a specific role
 * @access  Private (Requires view_organization_roles permission)
 */
export const getRolePermissions = asyncHandler(
  async (
    req: AuthRequest & { params: { orgId: string; roleId: string } },
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const { orgId, roleId } = req.params;
      const permissions = await organizationService.getRolePermissions(
        orgId,
        roleId,
      );
      res.status(200).json({ success: true, data: permissions });
    } catch (err) {
      next(err);
    }
  },
);
