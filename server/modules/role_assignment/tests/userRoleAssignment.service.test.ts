import mongoose from 'mongoose';
import { userRoleAssignmentService } from '../userRoleAssignment.service';
import User from '../../user/user.model';
import Role from '../../role/role.model';
import Organization from '../../organization/organization.model';
import UserRoleAssignment from '../userRoleAssignment.model';
import { PermissionScope } from '../../permission/permission.model';
import ErrorResponse from '../../../utils/errorResponse';
import { permissionCacheService } from '../../../shared/service/permissionCache.service';

jest.mock('../../user/user.model');
jest.mock('../../role/role.model');
jest.mock('../../organization/organization.model');
jest.mock('../userRoleAssignment.model');
jest.mock('../../../shared/service/permissionCache.service', () => ({
  permissionCacheService: {
    getPermissionIds: jest.fn(),
    setPermissionIds: jest.fn(),
    invalidateForUser: jest.fn(),
    invalidateForUsers: jest.fn(),
  },
}));

describe('UserRoleAssignmentService', () => {
  const validUserId = new mongoose.Types.ObjectId().toString();
  const validRoleId = new mongoose.Types.ObjectId().toString();
  const validOrgId = new mongoose.Types.ObjectId().toString();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('validateIds', () => {
    it('should throw if userId is invalid', async () => {
      await expect(
        (userRoleAssignmentService as any).validateIds('bad', validRoleId)
      ).rejects.toThrow(new ErrorResponse('Invalid User ID', 400));
    });

    it('should throw if roleId is invalid', async () => {
      await expect(
        (userRoleAssignmentService as any).validateIds(validUserId, 'bad')
      ).rejects.toThrow(new ErrorResponse('Invalid Role ID', 400));
    });

    it('should return objectIds for valid ids', async () => {
      const result = await (userRoleAssignmentService as any).validateIds(validUserId, validRoleId);
      expect(result.userObjectId).toBeInstanceOf(mongoose.Types.ObjectId);
      expect(result.roleObjectId).toBeInstanceOf(mongoose.Types.ObjectId);
    });
  });

  describe('validateScopeContext', () => {
    it('should return undefined for GLOBAL scope', async () => {
      const result = await (userRoleAssignmentService as any).validateScopeContext(PermissionScope.GLOBAL);
      expect(result).toBeUndefined();
    });

    it('should validate ORGANIZATION scope and return objectId', async () => {
      (Organization.exists as any).mockResolvedValue(true);
      const result = await (userRoleAssignmentService as any).validateScopeContext(PermissionScope.ORGANIZATION, validOrgId);
      expect(result).toBeInstanceOf(mongoose.Types.ObjectId);
      expect(Organization.exists).toHaveBeenCalledWith({ _id: new mongoose.Types.ObjectId(validOrgId) });
    });

    it('should throw if ORGANIZATION scopeId is invalid', async () => {
      await expect(
        (userRoleAssignmentService as any).validateScopeContext(PermissionScope.ORGANIZATION, 'bad')
      ).rejects.toThrow(new ErrorResponse('Valid organization ID (scopeId) is required', 400));
    });

    it('should throw if ORGANIZATION does not exist', async () => {
      (Organization.exists as any).mockResolvedValue(false);
      await expect(
        (userRoleAssignmentService as any).validateScopeContext(PermissionScope.ORGANIZATION, validOrgId)
      ).rejects.toThrow(new ErrorResponse('Organization context not found', 404));
    });
  });

  describe('assignRoleToUser', () => {
    it('should throw if user does not exist', async () => {
      (User.exists as any).mockResolvedValue(false);
      await expect(
        userRoleAssignmentService.assignRoleToUser(validUserId, validRoleId, PermissionScope.GLOBAL)
      ).rejects.toThrow(new ErrorResponse('User not found', 404));
    });

    it('should throw if role does not exist', async () => {
      (User.exists as any).mockResolvedValue(true);
      (Role.findById as any).mockReturnValue({ lean: jest.fn().mockResolvedValue(null) });
      await expect(
        userRoleAssignmentService.assignRoleToUser(validUserId, validRoleId, PermissionScope.GLOBAL)
      ).rejects.toThrow(new ErrorResponse('Role not found', 404));
    });

    it('should throw if role scope does not match', async () => {
      (User.exists as any).mockResolvedValue(true);
      (Role.findById as any).mockReturnValue({ lean: jest.fn().mockResolvedValue({ scope: PermissionScope.ORGANIZATION }) });
      await expect(
        userRoleAssignmentService.assignRoleToUser(validUserId, validRoleId, PermissionScope.GLOBAL)
      ).rejects.toThrow(new ErrorResponse('Role scope mismatch. Expected global, got organization', 400));
    });

    it('should throw if assignment fails to create', async () => {
      (User.exists as any).mockResolvedValue(true);
      (Role.findById as any).mockReturnValue({ lean: jest.fn().mockResolvedValue({ scope: PermissionScope.GLOBAL }) });
      (UserRoleAssignment.findOneAndUpdate as any).mockResolvedValue(null);
      await expect(
        userRoleAssignmentService.assignRoleToUser(validUserId, validRoleId, PermissionScope.GLOBAL)
      ).rejects.toThrow(new ErrorResponse('Failed to create role assignment', 500));
    });

    it('should throw 409 if duplicate assignment', async () => {
      (User.exists as any).mockResolvedValue(true);
      (Role.findById as any).mockReturnValue({ lean: jest.fn().mockResolvedValue({ scope: PermissionScope.GLOBAL }) });
      const dupError = new Error('Duplicate');
      (dupError as any).code = 11000;
      (UserRoleAssignment.findOneAndUpdate as any).mockImplementation(() => { throw dupError; });
      await expect(
        userRoleAssignmentService.assignRoleToUser(validUserId, validRoleId, PermissionScope.GLOBAL)
      ).rejects.toThrow(new ErrorResponse('User already has this role in the specified scope/context.', 409));
    });

    it('should assign global role successfully', async () => {
      (User.exists as any).mockResolvedValue(true);
      (Role.findById as any).mockReturnValue({ lean: jest.fn().mockResolvedValue({ scope: PermissionScope.GLOBAL }) });
      const assignment = { _id: 'assignmentId', userId: validUserId, roleId: validRoleId, scope: PermissionScope.GLOBAL };
      (UserRoleAssignment.findOneAndUpdate as any).mockResolvedValue(assignment);

      const result = await userRoleAssignmentService.assignRoleToUser(validUserId, validRoleId, PermissionScope.GLOBAL);
      expect(result).toEqual(assignment);
      expect(permissionCacheService.invalidateForUser).toHaveBeenCalled();
    });

    it('should assign organization role successfully', async () => {
      (User.exists as any).mockResolvedValue(true);
      (Role.findById as any).mockReturnValue({ lean: jest.fn().mockResolvedValue({ scope: PermissionScope.ORGANIZATION }) });
      (Organization.exists as any).mockResolvedValue(true);
      const assignment = { _id: 'assignmentId', userId: validUserId, roleId: validRoleId, scope: PermissionScope.ORGANIZATION, scopeId: validOrgId };
      (UserRoleAssignment.findOneAndUpdate as any).mockResolvedValue(assignment);

      const result = await userRoleAssignmentService.assignRoleToUser(validUserId, validRoleId, PermissionScope.ORGANIZATION, validOrgId);
      expect(result).toEqual(assignment);
      expect(permissionCacheService.invalidateForUser).toHaveBeenCalled();
    });

    it('should handle unexpected errors', async () => {
      (User.exists as any).mockResolvedValue(true);
      (Role.findById as any).mockImplementation(() => { throw new Error('DB error'); });
      await expect(
        userRoleAssignmentService.assignRoleToUser(validUserId, validRoleId, PermissionScope.GLOBAL)
      ).rejects.toThrow(ErrorResponse);
    });
  });

  describe('unassignRoleFromUser', () => {
    it('should unassign role and invalidate cache', async () => {
      (Organization.exists as any).mockResolvedValue(true);
      (UserRoleAssignment.findOneAndDelete as any).mockResolvedValue({ _id: 'assignmentId' });

      await userRoleAssignmentService.unassignRoleFromUser(
        validUserId,
        validRoleId,
        PermissionScope.ORGANIZATION,
        validOrgId,
      );

      expect(UserRoleAssignment.findOneAndDelete).toHaveBeenCalled();
      expect(permissionCacheService.invalidateForUser).toHaveBeenCalled();
    });

    it('should throw 404 when assignment does not exist', async () => {
      (Organization.exists as any).mockResolvedValue(true);
      (UserRoleAssignment.findOneAndDelete as any).mockResolvedValue(null);

      await expect(
        userRoleAssignmentService.unassignRoleFromUser(
          validUserId,
          validRoleId,
          PermissionScope.ORGANIZATION,
          validOrgId,
        ),
      ).rejects.toThrow(new ErrorResponse('Role assignment not found', 404));
    });
  });
});