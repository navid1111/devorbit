import express from 'express';
import multer from 'multer';

import { checkPermission, protect } from '../auth/auth.middleware';

import { standardApiLimiter } from '../../utils/rateLimiter';
import { getOrganizationRoles } from '../role/role.controller';
import { assignOrganizationRole } from '../role_assignment/userRoleAssignmentController';
import {
  assignOwner,
  createOrganization,
  createOrganizationRole,
  deleteOrganization,
  fetchOtherTurfs,
  getOrganization,
  getOrganizationRoleMembers,
  getOrganizationUnassignedUsers,
  updateOrganization,
  updateOrganizationRolePermissions,
} from './organization.controller';

const router = express.Router();

// Configure Multer for image uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 5 }, // 5MB limit, up to 5 files
});

// --- Organization CRUD ---

// Create Organization (Admin only)
router.post(
  '/',
  
  protect,

  checkPermission('create_organization'), // Global permission check
  upload.array('images', 5), // Handle images
  createOrganization,
);

// Assign Owner to Organization (Admin only)
router.post(
  '/:id/assign-owner',
  
  protect,
  checkPermission('assign_organization_owner'), // Global permission check
  assignOwner,
);

// Update Organization Details (Org Owner or role with permission)
router.put(
  '/:id',
  
  protect,
  checkPermission('update_organization'), // Organization-scoped permission check
  upload.array('images', 5), // Handle optional image updates
  updateOrganization,
);

// Delete Organization (Org Owner or Admin)
router.delete(
  '/:id',
  
  protect,

  checkPermission('delete_own_organization'), // Check this first (most common case)

  deleteOrganization,
);

// Get Organization Details
router.get('/:id', getOrganization);

router.post(
  '/:id/roles', // Use :id for organizationId for consistency
  
  protect,
  checkPermission('manage_organization_roles'), // Organization-scoped
  createOrganizationRole,
);

router.get(
  '/:organizationId/roles',
  
  protect,
  checkPermission('view_roles'),
  getOrganizationRoles,
);

router.post(
  '/:organizationId/users/:userId/assignments',
  
  protect,
  checkPermission('manage_organization_roles'),
  assignOrganizationRole,
);
router.get(
  '/:orgId/roles',
  protect,

  getOrganizationRoles,
);

// Get all members with roles in an organization
router.get(
  '/:orgId/role-members',
  protect,

  getOrganizationRoleMembers,
);

// Get all users without a role in the organization
router.get(
  '/:orgId/unassigned-users',
  protect,

  getOrganizationUnassignedUsers,
);

// Update permissions for a role in an organization
router.put(
  '/:orgId/roles/:roleId/permissions',
  protect,

  updateOrganizationRolePermissions,
);

// Fetch other turfs by organization excluding the given turf
router.get('/:organizationId/other-turfs/:turfId', fetchOtherTurfs);

export default router;
