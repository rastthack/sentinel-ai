/**
 * Intentionally vulnerable filesystem access.
 * Scanner validation only.
 */

import { Router } from "express";
import { readFile } from "node:fs";

const router = Router();

router.get("/files/:path", (req, res) => {
  readFile(req.params.path, (_error, data) => {
    res.send(data);
  });
});

export default router;
