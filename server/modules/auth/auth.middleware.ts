import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import UserRoleAssignment from "../role_assignment/userRoleAssignment.model";
import { IPermission, PermissionScope } from "./../permission/permission.model";

import mongoose, { Types } from "mongoose";
import User from "../../modules/user/user.model";
import ErrorResponse from "../../utils/errorResponse";

import Permission from "../permission/permission.model";
import { IRole } from "../role/role.model";
import { permissionCacheService } from "../../shared/service/permissionCache.service";

interface JwtPayload {
  id: string;
}

export interface AuthRequest extends Request {
  user?: {
    id: string;
    isAdmin?: boolean;
    isOrgOwner?: boolean;
  };
  organizationId?: string | mongoose.Types.ObjectId;
  eventId?: string | mongoose.Types.ObjectId;
}

// Update the interface to extend IPermission
interface IPermissionDocument extends IPermission {
  _id: Types.ObjectId;
  name: string;
  scope: PermissionScope;
  __v?: number;
}

export const protect = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    const token = req.cookies.token;
    const adminToken = req.cookies.admin_token;

    if (!token && !adminToken) {
      return next(
        new ErrorResponse("Not authorized to access this route. User needs to login or register.", 401)
      );
    }

    try {
      // Determine which token to use (priority: adminToken > token)
      const activeToken = adminToken ?? token;
      const decoded = jwt.verify(
        activeToken,
        process.env.JWT_SECRET!
      ) as JwtPayload;

      const user = await User.findById(decoded.id).select("-password");
      if (!user) {
        return next(new ErrorResponse("User not found", 404));
      }

      // Set user on request
      req.user = {
        id: user._id.toString(),
        isAdmin: Boolean(adminToken), // Set isAdmin based on which token was used
      };

      next();
    } catch (error) {
      return next(
        new ErrorResponse("Not authorized to access this route", 401)
      );
    }
  } catch (error: unknown) {
    // Properly type and handle the error
    if (error instanceof Error) {
      return next(new ErrorResponse(error.message, 500));
    }
    return next(
      new ErrorResponse("An unexpected authorization error occurred", 500)
    );
  }
};

async function validateRequiredPermission(permissionName: string): Promise<{
  permissionId: Types.ObjectId;
  scope: PermissionScope;
} | null> {
  const permission = await Permission.findOne({ name: permissionName })
    .select("_id name scope")
    .lean();

  if (!permission) {
    console.warn(`Permission '${permissionName}' not found in database.`);
    return null;
  }

  return {
    permissionId: permission._id as Types.ObjectId,
    scope: permission.scope,
  };
}

function getScopeContext(
  scope: PermissionScope,
  req: AuthRequest
): Types.ObjectId | null {
  const organizationId =
    req.query.organizationId ??
    req.organizationId ??
    req.params.id ??
    req.params.organizationId;
  const eventId = req.eventId ?? req.params.eventId;

  if (scope === PermissionScope.ORGANIZATION && organizationId) {
    return new mongoose.Types.ObjectId(organizationId as string);
  }
  if (scope === PermissionScope.EVENT && eventId) {
    return new mongoose.Types.ObjectId(eventId as string);
  }
  return null;
}

async function checkUserPermission(
  userId: Types.ObjectId,
  permissionId: Types.ObjectId,
  scope: PermissionScope,
  contextId?: Types.ObjectId
): Promise<boolean> {
  const query = {
    userId,
    scope,
    ...(contextId && { scopeId: contextId }),
  };

  const cachedPermissionIds = await permissionCacheService.getPermissionIds(
    userId,
    scope,
    contextId
  );

  if (cachedPermissionIds) {
    return cachedPermissionIds.includes(permissionId.toString());
  }

  const assignments = await UserRoleAssignment.findOne(query).populate<{
    roleId: IRole;
  }>({
    path: "roleId",
    select: "permissions",
    populate: {
      path: "permissions",
      select: "_id",
    },
  });

  const permissionIds = assignments?.roleId?.permissions
    ? assignments.roleId.permissions.map((p: { _id: Types.ObjectId }) => p._id.toString())
    : [];

  await permissionCacheService.setPermissionIds(userId, scope, permissionIds, contextId);

  return permissionIds.includes(permissionId.toString());
}

// Main middleware with reduced complexity
export const checkPermission = (requiredPermissionName: string) => {
  return async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
      if (!req.user) {
        return next(new ErrorResponse("User not authenticated", 401));
      }

      const permissionData = await validateRequiredPermission(
        requiredPermissionName
      );
      if (!permissionData) {
        return next(
          new ErrorResponse(
            `Permission '${requiredPermissionName}' is not configured.`,
            500
          )
        );
      }

      const contextId = getScopeContext(permissionData.scope, req);
      if (!contextId && permissionData.scope !== PermissionScope.GLOBAL) {
        return next(
          new ErrorResponse(
            `Context ID required for ${permissionData.scope} scope`,
            400
          )
        );
      }

      const hasPermission = await checkUserPermission(
        new mongoose.Types.ObjectId(req.user.id),
        permissionData.permissionId,
        permissionData.scope,
        contextId ?? undefined
      );

      if (hasPermission) {
        return next();
      }

      return next(
        new ErrorResponse(
          `Not authorized to perform: ${requiredPermissionName}`,
          403
        )
      );
    } catch (error: any) {
      if (error instanceof mongoose.Error.CastError) {
        return next(new ErrorResponse("Invalid ID format provided", 400));
      }
      console.error("Permission check error:", error);
      return next(new ErrorResponse("Authorization check failed", 500));
    }
  };
};

export const restrictToOrganizationMembers = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    if (!req.user) {
      return next(new ErrorResponse("User not authenticated", 401));
    }

    const organizationId = req.params.organizationId;

    if (!organizationId) {
      return next(
        new ErrorResponse(
          "Organization ID is required to access this resource",
          400
        )
      );
    }

    const roleAssignment = await UserRoleAssignment.findOne({
      userId: new mongoose.Types.ObjectId(req.user.id),
      scope: "organization",
      scopeId: new mongoose.Types.ObjectId(organizationId),
    });

    if (!roleAssignment) {
      return next(
        new ErrorResponse(
          "You are not authorized to access this organization dashboard",
          403
        )
      );
    }

    return next();
  } catch (error) {
    console.error("Authorization error:", error);
    return next(new ErrorResponse("Authorization failed", 500));
  }
};
