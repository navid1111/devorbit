// src/modules/health/health.controller.ts
import {  Response } from 'express';
import asyncHandler from '../../shared/middleware/async';
import HealthService from '../health-metrics/health-metrics.service';
import mongoose from 'mongoose';
import { AuthRequest } from '../auth/auth.middleware';

export default class HealthController {
  private readonly healthService: HealthService;

  constructor() {
    this.healthService = new HealthService();
  }

  /**
   * @route   HEAD /health
   * @desc    Basic health check for uptime monitoring
   * @access  Public
   */
  public basicHealthCheck = asyncHandler(
    async (req:AuthRequest, res: Response): Promise<void> => {
      const isDbConnected = mongoose.connection.readyState === 1; // 1 = connected
      res.status(isDbConnected ? 200 : 503).end();
    }
  );

  /**
   * @route   GET /health
   * @desc    Detailed health information
   * @access  Private
   * @permission get_health_check
   */
  public detailedHealthCheck = asyncHandler(
    async (req: AuthRequest, res: Response): Promise<void> => {
      const healthData = await this.healthService.getHealthData();
      res.status(healthData.status === 'ok' ? 200 : 503).json(healthData);
    }
  );

  /**
   * @route   GET /metrics
   * @desc    Prometheus metrics endpoint
   * @access  Private
   * @permission get_health_check
   */
  public getPrometheusMetrics = asyncHandler(
    async (req: AuthRequest, res: Response): Promise<void> => {
      const metrics = await this.healthService.getPrometheusMetrics();
      res.set('Content-Type', this.healthService.getPrometheusContentType());
      res.end(metrics);
    }
  );

  /**
   * @route   GET /api/v1/metrics/latest
   * @desc    Get the most recent metrics
   * @access  Private
   * @permission get_health_check
   */
  public getLatestMetrics = asyncHandler(
    async (req: AuthRequest, res: Response): Promise<void> => {
      const latestMetrics = await this.healthService.getLatestMetrics();
      
      res.status(200).json({
        success: true,
        metrics: latestMetrics
      });
    }
  );

  /**
   * @route   GET /api/v1/metrics/history
   * @desc    Get historical metrics
   * @access  Private
   * @permission get_health_check
   */
  public getMetricsHistory = asyncHandler(
    async (req: AuthRequest, res: Response): Promise<void> => {
      const hours = req.query.hours ? parseInt(req.query.hours as string) : 24;
      const interval = (req.query.interval as 'minute' | 'hour' | 'day') || 'hour';
      
      const metrics = await this.healthService.getMetricsHistory({
        hours,
        interval
      });
      
      res.status(200).json({
        success: true,
        metrics
      });
    }
  );
}