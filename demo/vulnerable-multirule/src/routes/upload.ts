/**
 * Intentionally unrestricted file upload.
 * Scanner validation only.
 */

import { Router } from "express";
import multer from "multer";

const router = Router();
const upload = multer().single("file");

router.post("/upload", upload, (_req, res) => {
  res.sendStatus(201);
});

export default router;
