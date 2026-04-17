import { NextFunction, Request, Response } from 'express';
import mongoose from 'mongoose';
import asyncHandler from '../../shared/middleware/async';
import { FilterOptions } from '../../types/filter.d';
import ErrorResponse from '../../utils/errorResponse';
import { ITurf } from './turf.model';
import TurfService from './turf.service';

export default class TurfController {
  private readonly turfService: TurfService;
  constructor() {
    this.turfService = new TurfService();
  }

  /**
 * @route POST /api/v1/turfs
 * @desc Create a new turf with details, images, and operating hours
 * @access Private/Admin
 */
  createTurf = asyncHandler(
    async (req: Request, res: Response, next: NextFunction) => {
      const {
        name,
        sports,
        basePrice,
        team_size,
        organization,
        operatingHours,
      } = req.body;
      const images = req.files as Express.Multer.File[];
      console.log(organization);
      try {
        // Validate required fields
        if (!name || !organization) {
          return next(new ErrorResponse('Name and organization are required', 400));
        }

        // Parse numeric fields
        const basePriceResult = this.parseBasePrice(basePrice);
        if (basePriceResult.error) {
          return next(basePriceResult.error);
        }

        // Parse sports
        const sportsResult = this.parseSports(sports);
        if (sportsResult.error) {
          return next(sportsResult.error);
        }

        // Parse operating hours
        const operatingHoursResult = this.parseOperatingHours(operatingHours);
        if (operatingHoursResult.error) {
          return next(operatingHoursResult.error);
        }

        // Parse team size
        const teamSizeResult = this.parseTeamSize(team_size);
        if (teamSizeResult.error) {
          return next(teamSizeResult.error);
        }

        // Combine all parsed data
        const turfData: Partial<ITurf> = {
          name,
          organization,
          ...basePriceResult.data,
          ...sportsResult.data,
          ...operatingHoursResult.data,
          ...teamSizeResult.data,
        };

        // Create the turf using the service
        const turf = await this.turfService.createTurf(turfData, images);

        res.status(201).json({
          success: true,
          data: turf,
          message: 'Turf created successfully',
        });
      } catch (error) {
        console.error('Error creating turf:', error);
        next(
          new ErrorResponse(
            `Failed to create turf: ${(error as Error).message}`,
            400,
          ),
        );
      }
    },
  );

  private async validateAndParseCreateData(data: {
    name: string;
    sports: any;
    basePrice: string | number;
    team_size: string | number;
    organization: string;
    operatingHours: any;
  }): Promise<Partial<ITurf> | null> {
    try {
      // Validate required fields
      if (!data.name || !data.organization) {
        throw new Error('Name and organization are required');
      }

      // Parse and validate fields using existing parser functions
      const [
        basePriceResult,
        sportsResult,
        operatingHoursResult,
        teamSizeResult,
      ] = await Promise.all([
        this.parseBasePrice(data.basePrice),
        this.parseSports(data.sports),
        this.parseOperatingHours(data.operatingHours),
        this.parseTeamSize(data.team_size),
      ]);

      // Check for validation errors
      const results = [
        basePriceResult,
        sportsResult,
        operatingHoursResult,
        teamSizeResult,
      ];
      const error = results.find(result => result.error);
      if (error) {
        throw error.error;
      }

      // Combine all parsed data
      return {
        name: data.name,
        organization: new mongoose.Types.ObjectId(data.organization),
        ...basePriceResult.data,
        ...sportsResult.data,
        ...operatingHoursResult.data,
        ...teamSizeResult.data,
      };
    } catch (error) {
      console.error('Error validating turf data:', error);
      throw error;
    }
  }

  /**
   * @route GET /api/v1/turfs
   * @desc Retrieve all turfs with optional basic filtering
   * @access Public
   */

  getTurfs = asyncHandler(
    async (req: Request, res: Response, next: NextFunction) => {
      const filter = req.query;
      const turfs = await this.turfService.getTurfs(filter);
      if (!turfs) {
        return next(new ErrorResponse('No turf found', 400));
      }

      res.status(200).json({
        success: true,
        data: turfs,
      });
    },
  );

  /**
   * @route GET /api/v1/turfs/:id
   * @desc Retrieve a specific turf by ID
   * @access Public
   */

  getTurfById = asyncHandler(
    async (req: Request, res: Response, next: NextFunction) => {
      const { id } = req.params;
      if (!mongoose.Types.ObjectId.isValid(id)) {
        return next(new ErrorResponse('Invalid Turf ID format', 404));
      }
      const turf = await this.turfService.getTurfById(id);
      if (!turf) {
        return next(new ErrorResponse('No turf found', 404));
      }

      res.status(200).json({
        success: true,
        data: turf,
      });
    },
  );

/**
 * @route PUT /api/v1/turfs/:id
 * @desc Update a turf's details and images by ID
 * @access Private/Admin
 */
  updateTurfById = asyncHandler(
    async (req: Request, res: Response, next: NextFunction) => {
      const { id } = req.params;
      // Remove organization from request body to prevent updates
      const { basePrice, operatingHours, sports, organization, ...rest } = req.body;

      // Notify if someone tried to update organization
      if (organization) {
        return next(new ErrorResponse('Organization cannot be changed for an existing turf', 400));
      }

      const newImages = req.files as Express.Multer.File[];

      if (!mongoose.Types.ObjectId.isValid(id)) {
        return next(new ErrorResponse('Invalid Turf ID format', 404));
      }

      try {
        const updateData = await this.validateAndParseUpdateData(
          { basePrice, operatingHours, sports, ...rest },
          next,
        );
        if (!updateData) return;

        const turf = await this.turfService.updateTurf(
          id,
          updateData,
          newImages,
        );
        if (!turf) return next(new ErrorResponse('No turf found', 404));

        res.status(200).json({
          success: true,
          data: turf,
          message: 'Turf updated successfully',
        });
      } catch (error) {
        next(error);
      }
    },
  );

  private async validateAndParseUpdateData(
    data: any,
    next: NextFunction,
  ): Promise<Partial<ITurf> | void> {
    try {
      const { basePrice, operatingHours, sports, team_size, ...rest } = data;
      const updateData: Partial<ITurf> = {};

      // Validate and parse all fields simultaneously
      const [
        basePriceResult,
        sportsResult,
        operatingHoursResult,
        teamSizeResult,
      ] = await Promise.all([
        this.parseBasePrice(basePrice),
        this.parseSports(sports),
        this.parseOperatingHours(operatingHours),
        this.parseTeamSize(team_size),
      ]);

      // Check for validation errors
      const validationResults = [
        basePriceResult,
        sportsResult,
        operatingHoursResult,
        teamSizeResult,
      ];

      // Find first error, if any
      const error = validationResults.find(result => result.error);
      if (error) {
        return next(error.error);
      }

      // Merge all valid results
      const parsedData = validationResults.reduce(
        (acc, result) => ({
          ...acc,
          ...result.data,
        }),
        {},
      );

      // Merge with rest of the data
      return {
        ...updateData,
        ...parsedData,
        ...rest,
      };
    } catch (error) {
      console.error('Error validating turf update data:', error);
      return next(
        new ErrorResponse(
          `Error processing update data: ${(error as Error).message}`,
          400,
        ),
      );
    }
  }

  // Update parser functions to not require next parameter
  private parseBasePrice(value: any) {
    if (!value) return { data: {} };
    const parsed = parseFloat(value);
    return isNaN(parsed)
      ? { error: new ErrorResponse('basePrice must be a valid number', 400) }
      : { data: { basePrice: parsed } };
  }

  private parseSports(value: any) {
    if (!value) return { data: {} };
    try {
      return {
        data: { sports: typeof value === 'string' ? JSON.parse(value) : value },
      };
    } catch {
      return { error: new ErrorResponse('Invalid sports format', 400) };
    }
  }

  private parseOperatingHours(value: any) {
    if (!value) return { data: {} };
    try {
      return {
        data: {
          operatingHours: typeof value === 'string' ? JSON.parse(value) : value,
        },
      };
    } catch {
      return { error: new ErrorResponse('Invalid operatingHours format', 400) };
    }
  }

  private parseTeamSize(value: any) {
    if (!value) return { data: {} };
    const parsed = parseInt(value);
    return isNaN(parsed)
      ? { error: new ErrorResponse('team_size must be a valid integer', 400) }
      : { data: { team_size: parsed } };
  }

  /**
   * @route DELETE /api/v1/turfs/:id
   * @desc Delete a turf by ID
   * @access Private/Admin
   */
  deleteTurfById = asyncHandler(
    async (req: Request, res: Response, next: NextFunction) => {
      const { id } = req.params;

      if (!mongoose.Types.ObjectId.isValid(id)) {
        return next(new ErrorResponse('Invalid Turf ID format', 404));
      }

      const turf = await this.turfService.deleteTurf(id);

      if (!turf) {
        return next(new ErrorResponse('No turf found', 404));
      }

      res.status(200).json({
        success: true,
        data: turf,
        message: 'Turf deleted successfully',
      });
    },
  );

  /**
   * @route GET /api/v1/turfs/filter
   * @desc Filter turfs by price, sports, location, availability, etc.
   * @access Public
   */

  filterTurfs = asyncHandler(
    async (req: Request, res: Response, next: NextFunction) => {
      // Extract filter options from query parameters
      const filterOptions: FilterOptions = {
        minPrice: req.query.minPrice as string,
        maxPrice: req.query.maxPrice as string,
        teamSize: req.query.teamSize as string,
        sports: req.query.sports as string | string[],
        facilities: req.query.facilities as string | string[],
        preferredDate: req.query.preferredDate as string,
        preferredTimeStart: req.query.preferredTimeStart as string,
        preferredTimeEnd: req.query.preferredTimeEnd as string,
        latitude: req.query.latitude as string,
        longitude: req.query.longitude as string,
        radius: req.query.radius as string,
        page: req.query.page as string,
        limit: req.query.limit as string,
      };

      const result = await this.turfService.filterTurfs(filterOptions);

      res.status(200).json(result);
    }
  );

  /**
   * @route GET /api/v1/turfs/:id/status
   * @desc Check if a turf is currently open or closed
   * @access Public
   */
  getTurfStatus = asyncHandler(
    async (req: Request, res: Response, next: NextFunction) => {
      const { id } = req.params;

      if (!mongoose.Types.ObjectId.isValid(id)) {
        return next(new ErrorResponse("Invalid Turf ID format", 404));
      }

      const status = await this.turfService.checkTurfStatus(id);

      res.status(200).json({
        success: true,
        data: status,
      });
    }
  );

  /**
 * @route GET /api/v1/turfs/organization/:organizationId
 * @desc Retrieve all turfs belonging to a specific organization
 * @access Public
 */
  getTurfsByOrganizationId = asyncHandler(
    async (req: Request, res: Response, next: NextFunction) => {
      const { organizationId } = req.params;

      if (!mongoose.Types.ObjectId.isValid(organizationId)) {
        return next(new ErrorResponse('Invalid Organization ID format', 400));
      }

      const turfs = await this.turfService.getTurfsByOrganizationId(organizationId);

      res.status(200).json({
        success: true,
        count: turfs.length,
        data: turfs,
      });
    }
  );
}
