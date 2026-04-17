import mongoose, { Types } from 'mongoose';
import ErrorResponse from '../../utils/errorResponse';
import Organization from '../organization/organization.model';
import { PermissionScope } from '../permission/permission.model';
import Role from '../role/role.model';
import User from '../user/user.model';
import UserRoleAssignment, {
  IUserRoleAssignment,
} from './userRoleAssignment.model';
import { permissionCacheService } from '../../shared/service/permissionCache.service';

class UserRoleAssignmentService {
  private async validateIds(
    userId: string,
    roleId: string,
  ): Promise<{ userObjectId: Types.ObjectId; roleObjectId: Types.ObjectId }> {
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      throw new ErrorResponse('Invalid User ID', 400);
    }
    if (!mongoose.Types.ObjectId.isValid(roleId)) {
      throw new ErrorResponse('Invalid Role ID', 400);
    }

    return {
      userObjectId: new Types.ObjectId(userId),
      roleObjectId: new Types.ObjectId(roleId),
    };
  }

  private async validateScopeContext(
    scope: PermissionScope,
    scopeId?: string,
  ): Promise<Types.ObjectId | undefined> {
    if (
      scope !== PermissionScope.ORGANIZATION &&
      scope !== PermissionScope.EVENT
    ) {
      return undefined;
    }

    if (!scopeId || !mongoose.Types.ObjectId.isValid(scopeId)) {
      throw new ErrorResponse(`Valid ${scope} ID (scopeId) is required`, 400);
    }

    const contextObjectId = new Types.ObjectId(scopeId);

    if (scope === PermissionScope.ORGANIZATION) {
      const orgExists = await Organization.exists({ _id: contextObjectId });
      if (!orgExists) {
        throw new ErrorResponse('Organization context not found', 404);
      }
    }

    return contextObjectId;
  }

  public async assignRoleToUser(
    userId: string,
    roleId: string,
    scope: PermissionScope,
    scopeId?: string,
  ): Promise<IUserRoleAssignment> {
    try {
      // Validate IDs and get ObjectIds
      const { userObjectId, roleObjectId } = await this.validateIds(
        userId,
        roleId,
      );

      // Check user exists
      const userExists = await User.exists({ _id: userObjectId });
      if (!userExists) {
        throw new ErrorResponse('User not found', 404);
      }

      // Check role exists and scope matches
      const role = await Role.findById(roleObjectId).lean();
      if (!role) {
        throw new ErrorResponse('Role not found', 404);
      }
      if (role.scope !== scope) {
        throw new ErrorResponse(
          `Role scope mismatch. Expected ${scope}, got ${role.scope}`,
          400,
        );
      }

      // Validate scope context
      const contextObjectId = await this.validateScopeContext(scope, scopeId);

      // Create assignment
      const assignment = await UserRoleAssignment.findOneAndUpdate(
        {
          userId: userObjectId,
          roleId: roleObjectId,
          scopeId: contextObjectId,
        },
        {
          $setOnInsert: {
            userId: userObjectId,
            roleId: roleObjectId,
            scope,
            ...(contextObjectId && { scopeId: contextObjectId }),
          },
        },
        { new: true, upsert: true, runValidators: true },
      );

      if (!assignment) {
        throw new ErrorResponse('Failed to create role assignment', 500);
      }

      await permissionCacheService.invalidateForUser(
        userObjectId,
        scope,
        contextObjectId,
      );

      return assignment;
    } catch (error: any) {
      if (error.code === 11000) {
        throw new ErrorResponse(
          'User already has this role in the specified scope/context.',
          409,
        );
      }
      console.error('Error assigning role:', error);
      throw new ErrorResponse(
        error.message ?? 'Failed to assign role',
        error.statusCode ?? 500,
      );
    }
  }

  public async unassignRoleFromUser(
    userId: string,
    roleId: string,
    scope: PermissionScope,
    scopeId?: string,
  ): Promise<void> {
    try {
      const { userObjectId, roleObjectId } = await this.validateIds(
        userId,
        roleId,
      );
      const contextObjectId = await this.validateScopeContext(scope, scopeId);

      const assignment = await UserRoleAssignment.findOneAndDelete({
        userId: userObjectId,
        roleId: roleObjectId,
        scope,
        ...(contextObjectId && { scopeId: contextObjectId }),
      });

      if (!assignment) {
        throw new ErrorResponse('Role assignment not found', 404);
      }

      await permissionCacheService.invalidateForUser(
        userObjectId,
        scope,
        contextObjectId,
      );
    } catch (error: any) {
      console.error('Error unassigning role:', error);
      throw new ErrorResponse(
        error.message ?? 'Failed to unassign role',
        error.statusCode ?? 500,
      );
    }
  }
}

export const userRoleAssignmentService = new UserRoleAssignmentService();
