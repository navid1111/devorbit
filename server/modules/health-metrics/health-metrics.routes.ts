
import express from 'express';
import { checkPermission, protect } from '../auth/auth.middleware';
import HealthController from '../health-metrics/health-metrics.controller';
import { standardApiLimiter } from '../../utils/rateLimiter';


const router = express.Router();
const healthController = new HealthController();

// Health check routes
router.head('/', healthController.basicHealthCheck);
router.get(
  '/',
  protect,
  checkPermission('get_health_check'),
  healthController.detailedHealthCheck,
); // global permission

// Prometheus metrics endpoint
const metricsRouter = express.Router();
metricsRouter.get(
  '/',
  protect,
  checkPermission('get_health_check'),
  healthController.getPrometheusMetrics,
);

// Metrics API endpoints
const metricsApiRouter = express.Router();
metricsApiRouter.get(
  '/latest',
  

  protect,
  checkPermission('get_health_check'),
  healthController.getLatestMetrics,
);
metricsApiRouter.get(
  '/history',
  
    protect,
  checkPermission('get_health_check'),
  healthController.getMetricsHistory,
);

export { router as healthRouter, metricsApiRouter, metricsRouter };
