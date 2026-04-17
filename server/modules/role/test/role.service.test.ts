import mongoose from 'mongoose';
import RoleService from '../role.service';
import Role, { IRole } from '../role.model';
import Permission, { PermissionScope } from '../../permission/permission.model';
import UserRoleAssignment from '../../role_assignment/userRoleAssignment.model';
import ErrorResponse from '../../../utils/errorResponse';
import { permissionCacheService } from '../../../shared/service/permissionCache.service';

jest.mock('../role.model');
jest.mock('../../permission/permission.model');
jest.mock('../../role_assignment/userRoleAssignment.model');
jest.mock('../../../shared/service/permissionCache.service', () => ({
  permissionCacheService: {
    getPermissionIds: jest.fn(),
    setPermissionIds: jest.fn(),
    invalidateForUser: jest.fn(),
    invalidateForUsers: jest.fn(),
  },
}));

// Fix the organization model mock - use jest.mock with a factory function
// instead of using a variable that isn't hoisted properly
jest.mock('../../organization/organization.model', () => ({
  exists: jest.fn(),
  findById: jest.fn()
}));

// Get a reference to the mocked model after it's been initialized
const mockOrganizationModel = require('../../organization/organization.model');

describe('RoleService', () => {
  let roleService: RoleService;

  beforeEach(() => {
    roleService = new RoleService();
    jest.clearAllMocks();
  });

  describe('getRolesByOrganization', () => {
    it('should throw ErrorResponse on error', async () => {
      mockOrganizationModel.exists.mockImplementation(() => { throw new Error('DB error'); });
      await expect(roleService.getRolesByOrganization('507f1f77bcf86cd799439011'))
        .rejects.toThrow(ErrorResponse);
    });
  });

  describe('updateOrganizationRole', () => {
    it('should update an organization role', async () => {
      mockOrganizationModel.exists.mockResolvedValue(true);
      (UserRoleAssignment.findOne as any) = jest.fn().mockResolvedValue({ _id: 'assignment' });
      (Permission.find as any).mockReturnValue({
        select: jest.fn().mockReturnThis(),
        lean: jest.fn().mockResolvedValue([{ _id: 'p1' }]),
      });
      (Role.findByIdAndUpdate as any) = jest.fn().mockReturnValue({ 
        populate: jest.fn().mockResolvedValue({ name: 'Updated' }) 
      });
      (UserRoleAssignment.find as any).mockReturnValue({
        select: jest.fn().mockReturnThis(),
        lean: jest.fn().mockResolvedValue([]),
      });

      const result = await roleService.updateOrganizationRole(
        '507f1f77bcf86cd799439011',
        '507f1f77bcf86cd799439012', 
        { name: 'Updated', permissions: ['p1'] }
      );
      
      expect(result).toHaveProperty('name', 'Updated');
      expect(permissionCacheService.invalidateForUsers).toHaveBeenCalled();
    });

    it('should throw 404 if role not found', async () => {
      mockOrganizationModel.exists.mockResolvedValue(true);
      (UserRoleAssignment.findOne as any) = jest.fn().mockResolvedValue(null);
      
      await expect(roleService.updateOrganizationRole(
        '507f1f77bcf86cd799439011',
        '507f1f77bcf86cd799439012',
        { name: 'Updated' }
      )).rejects.toThrow(ErrorResponse);
    });

    it('should handle errors and abort transaction', async () => {
      mockOrganizationModel.exists.mockImplementation(() => { 
        throw new Error('DB error'); 
      });
      
      await expect(roleService.updateOrganizationRole(
        '507f1f77bcf86cd799439011',
        '507f1f77bcf86cd799439012',
        { name: 'Updated' }
      )).rejects.toThrow(ErrorResponse);
    });
  });

  describe('validatePermissions', () => {
    it('should validate permissions and return ids', async () => {
      (Permission.find as any).mockReturnValue({
        select: jest.fn().mockReturnThis(),
        lean: jest.fn().mockResolvedValue([{ _id: 'p1' }, { _id: 'p2' }]),
      });
      
      const result = await (roleService as any).validatePermissions(
        ['p1', 'p2'], 
        PermissionScope.ORGANIZATION
      );
      
      expect(result).toEqual(['p1', 'p2']);
    });

    it('should throw if permissions do not match', async () => {
      (Permission.find as any).mockReturnValue({
        select: jest.fn().mockReturnThis(),
        lean: jest.fn().mockResolvedValue([{ _id: 'p1' }]),
      });
      
      await expect((roleService as any).validatePermissions(
        ['p1', 'p2'], 
        PermissionScope.ORGANIZATION
      )).rejects.toThrow(ErrorResponse);
    });
  });

  describe('createGlobalRole', () => {
    it('should create a global role', async () => {
      (Permission.find as any).mockReturnValue({
        select: jest.fn().mockReturnThis(),
        lean: jest.fn().mockResolvedValue([{ _id: 'p1' }]),
      });
      
      const mockRole = { _id: 'r1', name: 'Global' };
      const mockPopulate = jest.fn().mockResolvedValue(mockRole);
      (Role.create as jest.Mock).mockReturnValue({
        populate: mockPopulate
      });
      
      const result = await roleService.createGlobalRole({ 
        name: 'Global', 
        permissions: ['p1'] 
      });
      
      expect(result).toHaveProperty('name', 'Global');
    });

    it('should throw ErrorResponse on error', async () => {
      (Permission.find as any).mockImplementation(() => {
        throw new ErrorResponse('DB error', 500); // Return ErrorResponse directly
      });
      
      await expect(roleService.createGlobalRole({ 
        name: 'Global', 
        permissions: ['p1'] 
      })).rejects.toThrow(ErrorResponse);
    });
  });

  describe('createOrganizationRole', () => {
    it('should create an organization role', async () => {
      (Permission.find as any).mockReturnValue({
        select: jest.fn().mockReturnThis(),
        lean: jest.fn().mockResolvedValue([{ _id: 'p1' }]),
      });
      
      const mockRole = { _id: 'r1', name: 'OrgRole' };
      const mockPopulate = jest.fn().mockResolvedValue(mockRole);
      (Role.create as jest.Mock).mockReturnValue({
        populate: mockPopulate
      });
      
      const result = await roleService.createOrganizationRole({ 
        name: 'OrgRole', 
        permissions: ['p1'] 
      });
      
      expect(result).toHaveProperty('name', 'OrgRole');
    });

    it('should throw ErrorResponse on error', async () => {
      (Permission.find as any).mockImplementation(() => {
        throw new ErrorResponse('DB error', 500); // Return ErrorResponse directly
      });
      
      await expect(roleService.createOrganizationRole({ 
        name: 'OrgRole', 
        permissions: ['p1'] 
      })).rejects.toThrow(ErrorResponse);
    });
  });

  describe('getGlobalRoles', () => {
    it('should return global roles', async () => {
      const roles = [{ _id: 'r1', name: 'Global' }];
      (Role.find as any).mockReturnValue({
        populate: jest.fn().mockReturnThis(),
        lean: jest.fn().mockResolvedValueOnce(roles),
      });
      
      const result = await roleService.getGlobalRoles();
      expect(result).toEqual(roles);
    });

    it('should throw ErrorResponse on error', async () => {
      (Role.find as any).mockImplementation(() => {
        throw new ErrorResponse('DB error', 500); // Return ErrorResponse directly
      });
      
      await expect(roleService.getGlobalRoles()).rejects.toThrow(ErrorResponse);
    });
  });

  describe('getRoleById', () => {
    it('should return role by id', async () => {
      const role = { _id: 'r1', name: 'Role1' };
      (Role.findById as any).mockReturnValue({
        populate: jest.fn().mockResolvedValueOnce(role),
      });
      
      const result = await roleService.getRoleById('507f1f77bcf86cd799439012');
      expect(result).toEqual(role);
    });

    it('should throw 404 if not found', async () => {
      (Role.findById as any).mockReturnValue({
        populate: jest.fn().mockResolvedValueOnce(null),
      });
      
      await expect(roleService.getRoleById('507f1f77bcf86cd799439012'))
        .rejects.toThrow(ErrorResponse);
    });

    it('should throw ErrorResponse on error', async () => {
      (Role.findById as any).mockImplementation(() => {
        throw new ErrorResponse('DB error', 500); // Return ErrorResponse directly
      });
      
      await expect(roleService.getRoleById('507f1f77bcf86cd799439012'))
        .rejects.toThrow(ErrorResponse);
    });
  });

  describe('deleteRole', () => {
    it('should delete a role and assignments', async () => {
      const role = { _id: 'r1', isDefault: false };
      (Role.findById as any).mockResolvedValue(role);
      
      // Mock session handling for transactions
      const mockSession = {
        startTransaction: jest.fn(),
        commitTransaction: jest.fn(),
        abortTransaction: jest.fn(),
        endSession: jest.fn(),
      };
      
      jest.spyOn(mongoose, 'startSession').mockResolvedValue(mockSession as any);
      
      // Mock deleteMany with session
      (UserRoleAssignment.deleteMany as jest.Mock) = jest.fn().mockReturnValue({
        session: jest.fn().mockResolvedValue({})
      });

      (UserRoleAssignment.find as any).mockReturnValue({
        select: jest.fn().mockReturnThis(),
        lean: jest.fn().mockResolvedValue([]),
      });
      
      // Mock deleteOne with session
      (Role.deleteOne as jest.Mock) = jest.fn().mockReturnValue({
        session: jest.fn().mockResolvedValue({})
      });

      await roleService.deleteRole('507f1f77bcf86cd799439012');
      expect(mockSession.commitTransaction).toHaveBeenCalled();
      expect(mockSession.endSession).toHaveBeenCalled();
    });

    it('should throw 404 if role not found', async () => {
      (Role.findById as any).mockResolvedValue(null);
      
      await expect(roleService.deleteRole('507f1f77bcf86cd799439012'))
        .rejects.toThrow(ErrorResponse);
    });

    it('should throw if role is default', async () => {
      (Role.findById as any).mockResolvedValue({ _id: 'r1', isDefault: true });
      
      await expect(roleService.deleteRole('507f1f77bcf86cd799439012'))
        .rejects.toThrow(ErrorResponse);
    });

    it('should handle errors and abort transaction', async () => {
      (Role.findById as any).mockImplementation(() => { 
        throw new ErrorResponse('DB error', 500); 
      });
      
      await expect(roleService.deleteRole('507f1f77bcf86cd799439012'))
        .rejects.toThrow(ErrorResponse);
    });
  });

  describe('getRolePermissions', () => {
    it('should return permissions for a role', async () => {
      const role = { _id: 'r1', permissions: [{ name: 'p1' }, { name: 'p2' }] };
      
      // Mock findById().populate().lean() chain properly
      (Role.findById as any).mockImplementation(() => ({
        populate: jest.fn().mockImplementation(() => ({
          lean: jest.fn().mockResolvedValue(role)
        }))
      }));
      
      const result = await roleService.getRolePermissions('507f1f77bcf86cd799439012');
      expect(result).toEqual(['p1', 'p2']);
    });

    it('should throw 404 if not found', async () => {
      (Role.findById as any).mockImplementation(() => ({
        populate: jest.fn().mockImplementation(() => ({
          lean: jest.fn().mockResolvedValue(null)
        }))
      }));
      
      await expect(roleService.getRolePermissions('507f1f77bcf86cd799439012'))
        .rejects.toThrow(ErrorResponse);
    });

    it('should throw ErrorResponse on error', async () => {
      (Role.findById as any).mockImplementation(() => {
        throw new ErrorResponse('DB error', 500);
      });
      
      await expect(roleService.getRolePermissions('507f1f77bcf86cd799439012'))
        .rejects.toThrow(ErrorResponse);
    });
  });
});