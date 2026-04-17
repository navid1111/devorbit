import { Router } from "express";
import FacilityController from "./facility.controller";
import { checkPermission, protect } from "../auth/auth.middleware";
import { standardApiLimiter } from "../../utils/rateLimiter";


const router = Router();
const facilityController = new FacilityController();


router.post("/",protect, checkPermission("manage_tags"), facilityController.createFacility);
router.get("/",facilityController.getAllFacilities);
router.get("/:id", facilityController.getFacilityById);
router.put("/:id",protect, checkPermission("manage_tags"), facilityController.updateFacility);
router.delete("/:id",protect, checkPermission("manage_tags"), facilityController.deleteFacility);

export default router;