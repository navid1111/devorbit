import mongoose, { Types } from 'mongoose';
import ErrorResponse from '../../utils/errorResponse';
import Organization from '../organization/organization.model';
import Permission, { PermissionScope } from '../permission/permission.model';
import UserRoleAssignment from '../role_assignment/userRoleAssignment.model';
import Role, { IRole } from './role.model';
import { permissionCacheService } from '../../shared/service/permissionCache.service';

interface RoleUpdateData {
  name?: string;
  permissions?: string[];
}

interface RoleData {
  name: string;
  permissions: string[];
  isDefault?: boolean;
}

export default class RoleService {
  /**
   * Get all roles for an organization
   * @param organizationId - The ID of the organization
   * @returns Promise<IRole[]> - Array of roles
   */

  public async getRolesByOrganization(
    organizationId: string,
  ): Promise<IRole[]> {
    try {
      const orgObjectId = new mongoose.Types.ObjectId(organizationId);

      // Verify organization exists
      const organizationExists = await Organization.exists({
        _id: orgObjectId,
      });
      if (!organizationExists) {
        throw new ErrorResponse('Organization not found', 404);
      }

      // Find all role assignments for this organization
      const roleAssignments = await UserRoleAssignment.find({
        scope: PermissionScope.ORGANIZATION,
        scopeId: orgObjectId,
      }).distinct('roleId');

      // Get the actual roles with their permissions
      const roles = await Role.find({
        _id: { $in: roleAssignments },
      }).populate('permissions', 'name description');

      return roles;
    } catch (error: any) {
      console.error('Error fetching organization roles:', error);
      throw new ErrorResponse(
        error.message ?? 'Failed to fetch roles',
        error.statusCode ?? 500,
      );
    }
  }

  /**
   * Update an organization role
   * @param organizationId - The ID of the organization
   * @param roleId - The ID of the role to update
   * @param updateData - The data to update the role with
   * @returns Promise<IRole> - Updated role
   */
  public async updateOrganizationRole(
    organizationId: string,
    roleId: string,
    updateData: RoleUpdateData,
  ): Promise<IRole> {
    try {
      const orgObjectId = new mongoose.Types.ObjectId(organizationId);
      const roleObjectId = new mongoose.Types.ObjectId(roleId);

      // Verify organization exists
      const organizationExists = await Organization.exists({
        _id: orgObjectId,
      });
      if (!organizationExists) {
        throw new ErrorResponse('Organization not found', 404);
      }

      // Verify role exists and is assigned to this organization
      const roleAssignment = await UserRoleAssignment.findOne({
        roleId: roleObjectId,
        scope: PermissionScope.ORGANIZATION,
        scopeId: orgObjectId,
      });

      if (!roleAssignment) {
        throw new ErrorResponse('Role not found in this organization', 404);
      }

      // If updating permissions, verify they exist and are valid for organization scope
      let permissionIds: Types.ObjectId[] | undefined;
      if (updateData.permissions?.length) {
        const permissions = await Permission.find({
          _id: { $in: updateData.permissions },
          scope: PermissionScope.ORGANIZATION,
        })
          .select('_id')
          .lean<{ _id: Types.ObjectId }[]>();

        if (permissions.length !== updateData.permissions.length) {
          throw new ErrorResponse(
            'One or more invalid permission IDs provided',
            400,
          );
        }

        permissionIds = permissions.map(p => p._id);
      }

      // Update the role
      const updatedRole = await Role.findByIdAndUpdate(
        roleId,
        {
          $set: {
            ...(updateData.name && { name: updateData.name }),
            ...(permissionIds && { permissions: permissionIds }),
          },
        },
        {
          new: true,
          runValidators: true,
        },
      ).populate('permissions', 'name description');

      if (!updatedRole) {
        throw new ErrorResponse('Role not found', 404);
      }

      if (permissionIds) {
        const assignments = await UserRoleAssignment.find({
          roleId: roleObjectId,
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
      }

      return updatedRole;
    } catch (error: any) {
      console.error('Error updating organization role:', error);
      throw new ErrorResponse(
        error.message ?? 'Failed to update role',
        error.statusCode ?? 500,
      );
    }
  }

  /**
   * Validate permissions exist and match the required scope
   */
  private async validatePermissions(
    permissionIds: string[],
    requiredScope: PermissionScope,
  ): Promise<Types.ObjectId[]> {
    const permissions = await Permission.find({
      _id: { $in: permissionIds },
      scope: requiredScope,
    })
      .select('_id')
      .lean<{ _id: Types.ObjectId }[]>();

    if (permissions.length !== permissionIds.length) {
      throw new ErrorResponse(
        `One or more permissions are invalid or do not match the ${requiredScope} scope`,
        400,
      );
    }

    return permissions.map(p => p._id);
  }

  /**
   * Create a new global role
   */
  public async createGlobalRole(data: RoleData): Promise<IRole> {
    if (!data.name || !data.permissions?.length) {
      throw new ErrorResponse(
        'Role name and permissions array are required',
        400,
      );
    }

    const validatedPermissionIds = await this.validatePermissions(
      data.permissions,
      PermissionScope.GLOBAL,
    );

    try {
      const newRole = await Role.create({
        name: data.name,
        scope: PermissionScope.GLOBAL,
        permissions: validatedPermissionIds,
        isDefault: data.isDefault ?? false,
      });

      return newRole.populate('permissions', 'name scope');
    } catch (error: any) {
      if (error.code === 11000) {
        throw new ErrorResponse(
          `A global role named '${data.name}' already exists`,
          409,
        );
      }
      throw new ErrorResponse(
        error.message ?? 'Failed to create global role',
        500,
      );
    }
  }

  /**
   * Create a new organization-scoped role
   */
  public async createOrganizationRole(data: RoleData): Promise<IRole> {
    if (!data.name || !data.permissions?.length) {
      throw new ErrorResponse(
        'Role name and permissions array are required',
        400,
      );
    }

    const validatedPermissionIds = await this.validatePermissions(
      data.permissions,
      PermissionScope.ORGANIZATION,
    );

    try {
      const newRole = await Role.create({
        name: data.name,
        scope: PermissionScope.ORGANIZATION,
        permissions: validatedPermissionIds,
        isDefault: data.isDefault ?? false,
      });

      return newRole.populate('permissions', 'name scope');
    } catch (error: any) {
      if (error.code === 11000) {
        throw new ErrorResponse(
          `An organization-scoped role named '${data.name}' already exists`,
          409,
        );
      }
      throw new ErrorResponse(
        error.message ?? 'Failed to create organization role',
        500,
      );
    }
  }
  /**
   * Get all global roles
   */
  public async getGlobalRoles(): Promise<IRole[]> {
    try {
      return await Role.find({ scope: PermissionScope.GLOBAL })
        .populate('permissions', 'name description scope')
        .lean();
    } catch (error: any) {
      throw new ErrorResponse(
        error.message ?? 'Failed to fetch global roles',
        500,
      );
    }
  }
  /**
   * Get role by ID
   */
  public async getRoleById(roleId: string): Promise<IRole> {
    try {
      const role = await Role.findById(roleId).populate(
        'permissions',
        'name description scope',
      );

      if (!role) {
        throw new ErrorResponse('Role not found', 404);
      }

      return role;
    } catch (error: any) {
      throw new ErrorResponse(
        error.message ?? 'Failed to fetch role',
        error.statusCode ?? 500,
      );
    }
  }

  /**
   * Delete role by ID and remove all associated assignments
   */
  public async deleteRole(roleId: string): Promise<void> {
    try {
      const role = await Role.findById(roleId);
      if (!role) {
        throw new ErrorResponse('Role not found', 404);
      }

      if (role.isDefault) {
        throw new ErrorResponse('Cannot delete default roles', 400);
      }

      // Use a session to ensure both operations succeed or fail together
      const session = await mongoose.startSession();
      session.startTransaction();

      const assignmentsToDelete = await UserRoleAssignment.find({
        roleId: role._id,
      })
        .select('userId scope scopeId')
        .lean<
          { userId: Types.ObjectId; scope: PermissionScope; scopeId?: Types.ObjectId }[]
        >();

      try {
        // Delete all role assignments first
        await UserRoleAssignment.deleteMany({ roleId: role._id }).session(
          session,
        );

        // Then delete the role itself
        await Role.deleteOne({ _id: role._id }).session(session);

        // Commit the transaction
        await session.commitTransaction();

        // Invalidate after commit so removed users lose cached permissions immediately.
        await Promise.all(
          assignmentsToDelete.map(assignment =>
            permissionCacheService.invalidateForUser(
              assignment.userId,
              assignment.scope,
              assignment.scopeId,
            ),
          ),
        );
      } catch (error) {
        // If anything fails, rollback the transaction
        await session.abortTransaction();
        throw error;
      } finally {
        // End the session
        session.endSession();
      }
    } catch (error: any) {
      console.error('Error deleting role:', error);
      throw new ErrorResponse(
        error.message ?? 'Failed to delete role',
        error.statusCode ?? 500,
      );
    }
  }

  /**
   * Get all permissions for a role
   */
  public async getRolePermissions(roleId: string): Promise<string[]> {
    try {
      const role = await Role.findById(roleId)
        .populate('permissions', 'name')
        .lean();

      if (!role) {
        throw new ErrorResponse('Role not found', 404);
      }

      return role.permissions.map((permission: any) => permission.name);
    } catch (error: any) {
      throw new ErrorResponse(
        error.message ?? 'Failed to fetch role permissions',
        error.statusCode ?? 500,
      );
    }
  }
}

export const roleService = new RoleService();
