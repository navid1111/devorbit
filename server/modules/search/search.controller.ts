import { Request, Response } from 'express';
import Organization from '../organization/organization.model';
import { Turf } from '../turf/turf.model';

// Utility: Escape regex special characters
function escapeRegExp(input: string): string {
  return input.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Search suggestions endpoint
 * Returns quick suggestions for the search bar
 */
export const getSearchSuggestions = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    const { query } = req.query;
    if (!query || typeof query !== 'string' || query.trim().length < 2) {
      res.status(200).json({
        success: true,
        data: [],
      });
      return;
    }
    
    // FIX: Use escapeRegExp to prevent ReDoS vulnerability
    const sanitizedQuery = escapeRegExp(query.trim());
    const searchRegex = new RegExp(sanitizedQuery, 'i');
    const limit = 5;
    
    const turfs = await Turf.find({ name: searchRegex })
      .select('_id name sports team_size organization')
      .populate({
        path: 'organization',
        select: 'name location.city',
      })
      .limit(limit);
    
    const organizations = await Organization.find({
      $or: [
        { name: searchRegex },
        { 'location.address': searchRegex },
        { 'location.area': searchRegex },
        { 'location.city': searchRegex },
      ],
    })
      .select('_id name location.city')
      .limit(limit);
    
    const suggestions = [
      ...turfs.map(turf => {
        const orgData = turf.organization as unknown as {
          name: string;
          location: { city: string };
        };
        return {
          _id: turf._id,
          name: turf.name,
          type: 'turf' as const,
          location: orgData?.location?.city,
          sport: turf.sports?.[0],
        };
      }),
      ...organizations.map(org => ({
        _id: org._id,
        name: org.name,
        type: 'organization' as const,
        location: org.location?.city,
      })),
    ];
    
    const sortedSuggestions = [...suggestions].sort((a, b) => {
      // FIX: Use toLowerCase() on the query first to avoid repeated computations
      const queryLower = query.toLowerCase();
      const aStarts = a.name.toLowerCase().startsWith(queryLower) ? -1 : 0;
      const bStarts = b.name.toLowerCase().startsWith(queryLower) ? -1 : 0;
      return aStarts - bStarts;
    });
    
    res.status(200).json({
      success: true,
      data: sortedSuggestions.slice(0, limit),
    });
  } catch (error) {
    console.error('Search suggestions error:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching search suggestions',
      error: (error as Error).message,
    });
  }
};

/**
 * Main search endpoint
 * Handles comprehensive search with pagination
 */
const sanitizeSearchString = (input: unknown): string => {
  if (typeof input !== 'string') return '';
  // FIX: Apply escapeRegExp to prevent ReDoS vulnerability
  return escapeRegExp(input.slice(0, 100).trim());
};

export const search = async (req: Request, res: Response) => {
  try {
    const { query, location, sport, page = '1', limit = '10' } = req.query;
    
    // These calls to sanitizeSearchString already use escapeRegExp internally
    const searchQuery = sanitizeSearchString(query);
    const sportQuery = sanitizeSearchString(sport);
    const locationQuery = sanitizeSearchString(location);
    
    const pageNum = parseInt(page as string) || 1;
    const limitNum = parseInt(limit as string) || 10;
    const skip = (pageNum - 1) * limitNum;
    
    const pipeline: any[] = [];
    const matchConditions: any[] = [];
    
    if (searchQuery) {
      const searchRegex = new RegExp(searchQuery, 'i');
      matchConditions.push({ name: searchRegex });
    }
    
    if (sportQuery) {
      matchConditions.push({ sports: sportQuery });
    }
    
    if (matchConditions.length > 0) {
      pipeline.push({
        $match: { $or: matchConditions },
      });
    }
    
    pipeline.push({
      $lookup: {
        from: 'organizations',
        localField: 'organization',
        foreignField: '_id',
        as: 'organizationData',
      },
    });
    
    pipeline.push({
      $unwind: '$organizationData',
    });
    
    const orgConditions: any[] = [];
    
    if (searchQuery) {
      const searchRegex = new RegExp(searchQuery, 'i');
      orgConditions.push({ 'organizationData.name': searchRegex });
    }
    
    if (locationQuery) {
      const locRegex = new RegExp(locationQuery, 'i');
      orgConditions.push(
        { 'organizationData.location.address': locRegex },
        { 'organizationData.location.area': locRegex },
        { 'organizationData.location.sub_area': locRegex },
        { 'organizationData.location.city': locRegex },
      );
    }
    
    if (matchConditions.length > 0 && orgConditions.length > 0) {
      pipeline.splice(0, pipeline.length);
      pipeline.push({
        $lookup: {
          from: 'organizations',
          localField: 'organization',
          foreignField: '_id',
          as: 'organizationData',
        },
      });
      pipeline.push({
        $unwind: '$organizationData',
      });
      pipeline.push({
        $match: {
          $or: [{ $or: matchConditions }, { $or: orgConditions }],
        },
      });
    } else if (orgConditions.length > 0) {
      pipeline.push({
        $match: { $or: orgConditions },
      });
    }
    
    const countPipeline = [...pipeline];
    countPipeline.push({ $count: 'total' });
    const countResult = await Turf.aggregate(countPipeline);
    const total = countResult.length > 0 ? countResult[0].total : 0;
    
    pipeline.push({ $skip: skip });
    pipeline.push({ $limit: limitNum });
    pipeline.push({
      $project: {
        _id: 1,
        name: 1,
        basePrice: 1,
        sports: 1,
        team_size: 1,
        images: { $slice: ['$images', 1] },
        organization: {
          _id: '$organizationData._id',
          name: '$organizationData.name',
          location: {
            address: '$organizationData.location.address',
            city: '$organizationData.location.city',
          },
        },
      },
    });
    
    const results = await Turf.aggregate(pipeline);
    
    res.status(200).json({
      success: true,
      data: {
        results,
        pagination: {
          total,
          page: pageNum,
          limit: limitNum,
          pages: Math.ceil(total / limitNum),
        },
      },
    });
  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred during search',
      error: (error as Error).message,
    });
  }
};