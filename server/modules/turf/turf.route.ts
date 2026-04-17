import { Router } from "express";
import multer from "multer";
import TurfController from "./turf.controller";
import { protect } from "../auth/auth.middleware";
import { standardApiLimiter } from "../../utils/rateLimiter";

const router = Router();
const turfController = new TurfController();

// Configure Multer
const storage = multer.memoryStorage(); // Store files in memory
const upload = multer({
  storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit per file
    files: 5, // Maximum of 5 files
  },
  fileFilter: (req, file, cb) => {
    // Accept images only
    if (!file.mimetype.match(/^image\/(jpeg|png|jpg|gif)$/)) {
      return cb(new Error("Only image files are allowed!"));
    }
    cb(null, true);
  },
});

router.post("/",upload.array("images", 5),protect, turfController.createTurf);
router.get("/", turfController.getTurfs);
router.get("/:id", turfController.getTurfById);
router.put("/:id",protect, upload.array("images", 5), turfController.updateTurfById);
router.delete("/:id",protect, turfController.deleteTurfById);
router.get("/filter/search", turfController.filterTurfs);
router.get("/:id/status", turfController.getTurfStatus);
router.get("/organization/:organizationId", turfController.getTurfsByOrganizationId);



export default router;
