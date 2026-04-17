import { DeleteResult } from 'mongodb';
import mongoose, { Types } from 'mongoose';
import { deleteImage, uploadImage } from '../../utils/cloudinary';
import ErrorResponse from '../../utils/errorResponse';
import { extractPublicIdFromUrl } from '../../utils/extractUrl';
import FaciltyService from '../facility/facility.service';
import OrganizationRequestService from '../organization-request/organization-request.service';
import Permission, { PermissionScope } from '../permission/permission.model';
import Role, { IRole } from '../role/role.model';
import UserRoleAssignment from '../role_assignment/userRoleAssignment.model';
import User from '../user/user.model';
import { permissionCacheService } from '../../shared/service/permissionCache.service';

import { TurfReview } from '../turf-review/turf-review.model';
import { Turf } from '../turf/turf.model';
import Organization, { IOrganization } from './organization.model';

interface OrganizationDetails {
  name: string;
  facilities: string[];
  location: IOrganization['location'];
  orgContact: {
    phone: string;
    email: string;
  };
  images?: Express.Multer.File[];
  requestId?: string;
  adminId?: string;
  adminNotes?: string;
}
export interface IOrganizationRoleAssignment {
  organizationId: Types.ObjectId;
  role: Types.ObjectId;
}

class OrganizationService {
  organizationRequestService = new OrganizationRequestService();
  facilityService = new FaciltyService();

  /**
   * Create a new organization (Admin only)
   * Called by an Admin. Owner is assigned in a separate step if no requestId is provided.
   * If requestId is provided, owner is assigned as part of the creation process.
   * All operations are executed atomically within a transaction when requestId is provided.
   * @param name - Organization name
   * @param facilities - List of facilities
   * @param images - Array of image files
   * @param location - Location object
   * @param requestId - Optional organization request ID
   * @param adminId - ID of admin creating the organization
   * @param adminNotes - Optional notes from admin
   * @returns Promise<IOrganization>
   */

  public async createOrganization(
    orgDetails: OrganizationDetails,
  ): Promise<IOrganization | null> {
    try {
      const {
        name,
        facilities,
        location,
        orgContact: { phone: orgContactPhone, email: orgContactEmail },
        images = [],
        requestId,
        adminId,
        adminNotes,
      } = orgDetails;
      // Validate facilities
      await this.facilityService.validateFacilities(facilities);

      let imageUrls: string[] = [];

      // Only process images if they exist
      if (images && images.length > 0) {
        const imageUploads = images.map(image => uploadImage(image));
        const uploadedImages = await Promise.all(imageUploads);
        imageUrls = uploadedImages.map(img => img.url);
      }

     
      if (!requestId) {
        console.log(
          'requestId not provided, skipping request approval process.',
        );
      } else {
        console.log(
          'requestId provided, will approve the request after creating the organization.',
        );
      }

      // If requestId is provided, use a transaction to ensure atomicity
      if (requestId && adminId) {
        const session = await mongoose.startSession();

        try {
          let organization = null;
          let wasEdited = false;

          // Execute all operations within a transaction

          await session.withTransaction(async () => {
            // Create organization with basic information - using exact name without sanitization
            organization = new Organization({
              name, // Use the name exactly as provided
              facilities,
              orgContactPhone,
              orgContactEmail,
              images: imageUrls,
              location,
            });

            await organization.save({ session });

            // Get the request to extract the owner email
            const OrganizationRequest = mongoose.model('OrganizationRequest');
            const request = await OrganizationRequest.findById(
              requestId,
            ).session(session);
            if (!request) {
              throw new ErrorResponse('Organization request not found', 404);
            }

            // Find the owner user from the request's ownerEmail
            const owner = await User.findOne({ email: request.ownerEmail })
              .collation({ locale: 'en', strength: 2 })
              .session(session);

            if (!owner) {
              throw new ErrorResponse('Owner user not found', 404);
            }

            if (!organization?._id) {
              throw new ErrorResponse('Organization ID not found', 404);
            }

            // Assign the default organization owner role
            await this.assignOwnerToOrganizationWithSession(
              organization.id,
              owner.id,
              session,
            );

            // Check if data was edited from the original request
            wasEdited =
              await this.organizationRequestService.wasRequestDataEdited(
                requestId,
                name,
                facilities,
                location,
                orgContactPhone,
                orgContactEmail,
              );

            // Approve the request with the newly created organization ID
            await this.organizationRequestService.approveRequestWithSession(
              requestId,
              adminId,
              organization.id,
              wasEdited,
              adminNotes,
              session,
            );

            console.log(
              `Organization request ${requestId} approved and linked to organization ${organization.id}`,
            );
          });

          return organization;
        } catch (error) {
          console.error(
            'Failed to create organization and process request:',
            error,
          );
          throw error; // Rethrow the error to be handled by the caller
        } finally {
          session.endSession();
        }
      } else {
        // Standard flow without transaction when no requestId is provided
        const organization = new Organization({
          name,
          facilities,
          images: imageUrls,
          location,
          orgContactPhone,
          orgContactEmail,
        });

        await organization.save();
        return organization;
      }
    } catch (error) {
      console.error(error);
      throw new ErrorResponse('Failed to create organization', 500);
    }
  }

  /**
   * Assign a user as the owner of an organization (Admin only)
   * Creates the default 'Organization Owner' role for this org and assigns it.
   * @param organizationId - The ID of the organization
   * @param userId - The ID of the user to be assigned as owner
   * @returns Promise<IOrganization> - Updated organization
   */
  public async assignOwnerToOrganization(
    organizationId: string,
    userId: string,
  ): Promise<IOrganization> {
    // Use the session version with no session for backward compatibility
    return this.assignOwnerToOrganizationWithSession(organizationId, userId);
  }

  /**
   * Assign a user as the owner of an organization with optional session for transaction support
   * @param organizationId - The ID of the organization
   * @param userId - The ID of the user to be assigned as owner
   * @param session - Optional mongoose session for transaction support
   * @returns Promise<IOrganization> - Updated organization
   */
  private async assignOwnerToOrganizationWithSession(
    organizationId: string,
    userId: string,
    session?: mongoose.ClientSession,
  ): Promise<IOrganization> {
    try {
      const options = session ? { session } : {};

      const organization = await Organization.findById(organizationId).session(
        session || null,
      );
      if (!organization) throw new ErrorResponse('Organization not found', 404);

      const user = await User.findById(userId).session(session || null);
      if (!user) throw new ErrorResponse('User not found', 404);

      // 1. Define the role name and get permissions
      const ownerRoleName = 'Organization Owner';
      const orgPermissions = await Permission.find({
        scope: PermissionScope.ORGANIZATION,
      })
        .select('_id')
        .session(session || null);

      // 2. Find or create the owner role (without scopeId)
      const ownerRole = await Role.findOneAndUpdate(
        {
          name: ownerRoleName,
          scope: PermissionScope.ORGANIZATION,
        },
        {
          $set: {
            name: ownerRoleName,
            scope: PermissionScope.ORGANIZATION,
            permissions: orgPermissions.map(p => p._id),
            isDefault: true,
          },
        },
        {
          upsert: true,
          new: true,
          runValidators: true,
          ...options,
        },
      );

      if (!ownerRole) {
        throw new ErrorResponse(
          'Failed to find or create Organization Owner role',
          500,
        );
      }

      // 3. Create/Update role assignment in junction table
      await UserRoleAssignment.findOneAndUpdate(
        {
          userId: user._id,
          roleId: ownerRole._id,
          scope: PermissionScope.ORGANIZATION,
          scopeId: organization._id,
        },
        {
          $set: {
            userId: user._id,
            roleId: ownerRole._id,
            scope: PermissionScope.ORGANIZATION,
            scopeId: organization._id,
          },
        },
        {
          upsert: true,
          runValidators: true,
          ...options,
        },
      );

      // 4. Update organization with owner
      await organization.save(options);

      console.log(
        `User ${user.email} assigned as owner of organization ${organization.name}`,
      );
      return organization;
    } catch (error: any) {
      console.error('Error assigning organization owner:', error);
      throw new ErrorResponse(
        error.message ?? 'Failed to assign owner',
        error.statusCode ?? 500,
      );
    }
  }

  /**
   * Get organization details by ID
   * @param id - Organization ID
   * @returns Promise<IOrganization | null>
   */
  public async getOrganizationById(id: string): Promise<IOrganization | null> {
    try {
      const organization = await Organization.findById(id)
        .populate('turfs')
        .lean();

      if (!organization) {
        throw new ErrorResponse('Organization not found', 404);
      }

      return organization;
    } catch (error) {
      console.error('Error fetching organization:', error);
      throw new ErrorResponse('Failed to fetch organization', 500);
    }
  }

  /**
   * Update an organization
   * @param id - Organization ID
   * @param updateData - Partial organization data
   * @param newImages - Array of new image files (optional)
   * @returns Promise<IOrganization | null>
   */
  public async updateOrganization(
    id: string,
    updateData: Partial<IOrganization>,
    newImages?: Express.Multer.File[],
  ): Promise<IOrganization | null> {
    try {
      const organization = await Organization.findById(id);
      if (!organization) throw new ErrorResponse('Organization not found', 404);

      // Validate facilities if they're being updated
      if (updateData.facilities && updateData.facilities.length > 0) {
        await this.facilityService.validateFacilities(updateData.facilities);
      }

      // Handle image updates
      if (newImages && newImages.length > 0) {
        // Upload new images
        const newImageUploads = newImages.map(image => uploadImage(image));
        const uploadedNewImages = await Promise.all(newImageUploads);
        const newImageUrls = uploadedNewImages.map(img => img.url);

        // Delete old images from Cloudinary
        if (organization.images.length > 0) {
          await Promise.all(
            organization.images.map(imgUrl => {
              const publicId = extractPublicIdFromUrl(imgUrl);
              return publicId ? deleteImage(publicId) : Promise.resolve();
            }),
          );
        }

        updateData.images = newImageUrls;
      }

      // Update organization
      const updatedOrganization = await Organization.findByIdAndUpdate(
        id,
        updateData,
        { new: true, runValidators: true },
      );

      return updatedOrganization;
    } catch (error) {
      console.error(error);
      throw new ErrorResponse('Failed to update organization', 500);
    }
  }

  /**
   * Delete an organization and all associated resources
   * @param id - Organization ID
   * @returns Promise<DeleteResult>
   */
  public async deleteOrganization(id: string): Promise<DeleteResult> {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      const organization = await Organization.findById(id);
      if (!organization) throw new ErrorResponse('Organization not found', 404);

      // Delete images from Cloudinary
      if (organization.images.length > 0) {
        await Promise.all(
          organization.images.map(imgUrl => {
            const publicId = extractPublicIdFromUrl(imgUrl);
            return publicId ? deleteImage(publicId) : Promise.resolve();
          }),
        );
      }

      // Find all turfs associated with this organization
      const turfs = await Turf.find({ organization: id }).session(session);

      // Process each turf and its associated reviews
      for (const turf of turfs) {
        // Find all reviews for this turf
        const turfReviews = await TurfReview.find({ turf: turf._id }).session(
          session,
        );

        // Process each review - delete its images and remove references from user models
        for (const review of turfReviews) {
          // Delete review images from Cloudinary if they exist
          if (review.images && review.images.length > 0) {
            await Promise.all(
              review.images.map(imgUrl => {
                const publicId = extractPublicIdFromUrl(imgUrl);
                return publicId ? deleteImage(publicId) : Promise.resolve();
              }),
            );
          }

          // Remove review reference from user's document
          await User.findByIdAndUpdate(
            review.user,
            { $pull: { reviews: review._id } },
            { session },
          );
        }

        // Delete all reviews for this turf
        await TurfReview.deleteMany({ turf: turf._id }).session(session);

        // Delete turf images from Cloudinary
        if (turf.images && turf.images.length > 0) {
          await Promise.all(
            turf.images.map(imgUrl => {
              const publicId = extractPublicIdFromUrl(imgUrl);
              return publicId ? deleteImage(publicId) : Promise.resolve();
            }),
          );
        }
      }

      // Delete all turfs for this organization
      await Turf.deleteMany({ organization: id }).session(session);

      // Delete role assignments for this organization
      await UserRoleAssignment.deleteMany({
        scope: PermissionScope.ORGANIZATION,
        scopeId: id,
      }).session(session);

      // Delete custom roles for this organization
      await Role.deleteMany({
        scope: PermissionScope.ORGANIZATION,
        scopeId: id,
      }).session(session);

      // Delete the organization itself
      const deleteResult = await Organization.deleteOne({ _id: id }).session(
        session,
      );

      await session.commitTransaction();
      return deleteResult;
    } catch (error) {
      await session.abortTransaction();
      console.error('Error deleting organization:', error);
      throw new ErrorResponse('Failed to delete organization', 500);
    } finally {
      session.endSession();
    }
  }

  /**
   * Create a new role within an organization (Requires 'manage_organization_roles')
   * @param organizationId
   * @param roleName
   * @param permissionNames - Array of permission NAMES (e.g., ['create_turf', 'view_organization_reports'])
   */
  public async createOrganizationRole(
    organizationId: string,
    roleName: string,
    permissionNames: string[],
  ): Promise<IRole> {
    // Permission check ('manage_organization_roles') in middleware
    try {
      const organization = await Organization.findById(organizationId);
      if (!organization) throw new ErrorResponse('Organization not found', 404);
     
      // Validate role name uniqueness within this org
      const existingRole = await Role.findOne({
        name: roleName,
        scope: PermissionScope.ORGANIZATION,
        
      });
      if (existingRole)
        throw new ErrorResponse(
          `Role '${roleName}' already exists in this organization`,
          400,
        );

      // Validate permissions exist and are correctly scoped
      const permissions = await Permission.find({
        name: { $in: permissionNames },
        scope: PermissionScope.ORGANIZATION, // Ensure only org-scoped permissions are assigned
      }).select('_id name');

      const foundPermissionNames = permissions.map(p => p.name);
      const notFoundPermissions = permissionNames.filter(
        name => !foundPermissionNames.includes(name),
      );
      if (notFoundPermissions.length > 0) {
        throw new ErrorResponse(
          `Invalid or non-organizational permissions specified: ${notFoundPermissions.join(
            ', ',
          )}`,
          400,
        );
      }

      const newRole = await Role.create({
        name: roleName,
        scope: PermissionScope.ORGANIZATION,
        scopeId: organizationId,
        permissions: permissions.map(p => p._id),
        isDefault: false, // Custom roles are not default
      });

      return newRole;
    } catch (error: any) {
      console.error('Error creating organization role:', error);
      throw new ErrorResponse(
        error.message ?? 'Failed to create role',
        error.statusCode ?? 500,
      );
    }
  }

  /**
   * Fetch other turfs from the same organization excluding the current turf
   * @param organizationId - The ID of the organization
   * @param excludeTurfId - The ID of the turf to exclude
   */
  getOtherTurfsByOrganization = async (
    organizationId: string,
    excludeTurfId: string,
  ) => {
    if (
      !mongoose.Types.ObjectId.isValid(organizationId) ||
      !mongoose.Types.ObjectId.isValid(excludeTurfId)
    ) {
      throw new Error('Invalid organization or turf ID.');
    }

    return await Turf.find({
      organization: organizationId,
      _id: { $ne: excludeTurfId },
    })
      .limit(6)
      .populate('organization');
  };

  async getOrganizationRoles(orgId: string) {
    return Role.find({
      scope: PermissionScope.ORGANIZATION,
      scopeId: orgId,
    });
  }

  async getOrganizationRoleMembers(orgId: string) {
    return UserRoleAssignment.find({
      scope: PermissionScope.ORGANIZATION,
      scopeId: orgId,
    })
      .populate('userId')
      .populate('roleId');
  }

  async getOrganizationUnassignedUsers(orgId: string) {
    const assignedUserIds = await UserRoleAssignment.find({
      scope: PermissionScope.ORGANIZATION,
      scopeId: orgId,
    }).distinct('userId');
    return User.find({ _id: { $nin: assignedUserIds } });
  }

  async updateOrganizationRolePermissions(
    orgId: string,
    roleId: string,
    permissions: string[],
  ) {
    const updatedRole = await Role.findOneAndUpdate(
      { _id: roleId, scope: PermissionScope.ORGANIZATION, scopeId: orgId },
      { permissions },
      { new: true },
    );

    if (!updatedRole) {
      return updatedRole;
    }

    const orgObjectId = new Types.ObjectId(orgId);
    const assignments = await UserRoleAssignment.find({
      roleId: updatedRole._id,
      scope: PermissionScope.ORGANIZATION,
      scopeId: orgObjectId,
    })
      .select('userId')
      .lean<{ userId: Types.ObjectId }[]>();

    await permissionCacheService.invalidateForUsers(
      assignments.map(assignment => assignment.userId),
      PermissionScope.ORGANIZATION,
      orgObjectId,
    );

    return updatedRole;
  }

  async assignUserToOrganizationRole(
    orgId: string,
    userId: string,
    roleId: string,
  ) {
    // Verify the role belongs to this organization
    const role = await Role.findOne({
      _id: roleId,
      scope: PermissionScope.ORGANIZATION,
      scopeId: orgId,
    });

    if (!role) {
      throw new ErrorResponse('Role not found in this organization', 404);
    }

    // Verify user exists
    const user = await User.findById(userId);
    if (!user) {
      throw new ErrorResponse('User not found', 404);
    }

    // Check if assignment already exists
    const existingAssignment = await UserRoleAssignment.findOne({
      userId,
      roleId,
      scope: PermissionScope.ORGANIZATION,
      scopeId: orgId,
    });

    if (existingAssignment) {
      throw new ErrorResponse(
        'User already has this role in the organization',
        400,
      );
    }

    // Create new role assignment
    const roleAssignment = await UserRoleAssignment.create({
      userId,
      roleId,
      scope: PermissionScope.ORGANIZATION,
      scopeId: orgId,
    });

    return roleAssignment;
  }

  async getRolePermissions(orgId: string, roleId: string) {
    // Find the role and ensure it belongs to this organization
    const role = await Role.findOne({
      _id: roleId,
      scope: PermissionScope.ORGANIZATION,
      scopeId: orgId,
    });

    if (!role) {
      throw new ErrorResponse('Role not found in this organization', 404);
    }

    // Return the permissions array from the role
    return role.permissions;
  }
}

export const organizationService = new OrganizationService();
