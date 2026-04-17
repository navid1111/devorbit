import mongoose from 'mongoose';
import { checkPermission, AuthRequest } from '../auth.middleware';
import { PermissionScope } from '../../permission/permission.model';
import Permission from '../../permission/permission.model';
import UserRoleAssignment from '../../role_assignment/userRoleAssignment.model';
import { permissionCacheService } from '../../../shared/service/permissionCache.service';
import ErrorResponse from '../../../utils/errorResponse';

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

describe('checkPermission middleware', () => {
  const userId = new mongoose.Types.ObjectId();
  const organizationId = new mongoose.Types.ObjectId();
  const permissionId = new mongoose.Types.ObjectId();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('uses cache on hit and skips assignment query', async () => {
    (Permission.findOne as unknown as jest.Mock).mockReturnValue({
      select: jest.fn().mockReturnThis(),
      lean: jest.fn().mockResolvedValue({
        _id: permissionId,
        scope: PermissionScope.ORGANIZATION,
      }),
    });

    (permissionCacheService.getPermissionIds as jest.Mock).mockResolvedValue([
      permissionId.toString(),
    ]);

    const middleware = checkPermission('manage_organization_roles');
    const req = {
      user: { id: userId.toString() },
      params: { organizationId: organizationId.toString() },
      query: {},
    } as unknown as AuthRequest;
    const res = {} as any;
    const next = jest.fn();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalledWith();
    expect(UserRoleAssignment.findOne).not.toHaveBeenCalled();
    expect(permissionCacheService.getPermissionIds).toHaveBeenCalled();
  });

  it('queries DB and populates cache on miss', async () => {
    (Permission.findOne as unknown as jest.Mock).mockReturnValue({
      select: jest.fn().mockReturnThis(),
      lean: jest.fn().mockResolvedValue({
        _id: permissionId,
        scope: PermissionScope.ORGANIZATION,
      }),
    });

    (permissionCacheService.getPermissionIds as jest.Mock).mockResolvedValue(null);

    (UserRoleAssignment.findOne as unknown as jest.Mock).mockReturnValue({
      populate: jest.fn().mockResolvedValue({
        roleId: {
          permissions: [{ _id: permissionId }],
        },
      }),
    });

    const middleware = checkPermission('manage_organization_roles');
    const req = {
      user: { id: userId.toString() },
      params: { organizationId: organizationId.toString() },
      query: {},
    } as unknown as AuthRequest;
    const res = {} as any;
    const next = jest.fn();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalledWith();
    expect(UserRoleAssignment.findOne).toHaveBeenCalled();
    expect(permissionCacheService.setPermissionIds).toHaveBeenCalledWith(
      expect.any(mongoose.Types.ObjectId),
      PermissionScope.ORGANIZATION,
      [permissionId.toString()],
      expect.any(mongoose.Types.ObjectId),
    );
  });

  it('returns 403 when permission is not granted', async () => {
    (Permission.findOne as unknown as jest.Mock).mockReturnValue({
      select: jest.fn().mockReturnThis(),
      lean: jest.fn().mockResolvedValue({
        _id: permissionId,
        scope: PermissionScope.ORGANIZATION,
      }),
    });

    (permissionCacheService.getPermissionIds as jest.Mock).mockResolvedValue([]);

    const middleware = checkPermission('manage_organization_roles');
    const req = {
      user: { id: userId.toString() },
      params: { organizationId: organizationId.toString() },
      query: {},
    } as unknown as AuthRequest;
    const res = {} as any;
    const next = jest.fn();

    await middleware(req, res, next);

    const err = next.mock.calls[0][0] as ErrorResponse;
    expect(err).toBeInstanceOf(ErrorResponse);
    expect(err.statusCode).toBe(403);
    expect(err.message).toContain('Not authorized to perform');
  });
});
