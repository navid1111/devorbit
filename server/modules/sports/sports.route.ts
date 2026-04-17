import { Router } from "express";
import SportsController from "./sports.controller";
import { checkPermission, protect } from "../auth/auth.middleware";
import { standardApiLimiter } from "../../utils/rateLimiter";


const router = Router();
const sportsController = new SportsController();

router.post("/", sportsController.createSports);
router.get("/",sportsController.getAllSports);
router.get("/:id", sportsController.getSportsById);
router.put("/:id",protect, checkPermission("manage_tags"), sportsController.updateSports);
router.delete("/:id",protect, checkPermission("manage_tags"), sportsController.deleteSports);

export default router;