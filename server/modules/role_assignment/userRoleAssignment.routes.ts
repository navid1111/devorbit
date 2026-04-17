import express from 'express';
import { checkPermission, protect } from '../auth/auth.middleware';
import {
  assignGlobalRole,
  assignOrganizationRole,
  unassignGlobalRole,
  unassignOrganizationRole,
} from './userRoleAssignmentController';
import { standardApiLimiter } from '../../utils/rateLimiter';

const router = express.Router();

// Protect all routes
router.use(protect);

// Global role assignment
router.post(
  '/users/:userId/assignments/global',
  
  checkPermission('manage_user_global_roles'),
  assignGlobalRole,
);

router.delete(
  '/users/:userId/assignments/global/:roleId',
  checkPermission('manage_user_global_roles'),
  unassignGlobalRole,
);

// Organization role assignment
router.post(
  '/organizations/:organizationId/users/:userId/assignments',
  
  checkPermission('manage_organization_roles'),
  assignOrganizationRole,
);

router.delete(
  '/organizations/:organizationId/users/:userId/assignments/:roleId',
  checkPermission('manage_organization_roles'),
  unassignOrganizationRole,
);

export default router;
