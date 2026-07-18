/**
 * Intentionally vulnerable shell execution.
 * Scanner validation only.
 *
 * This fixture must not be executed.
 */

import { Router } from "express";
import { exec } from "node:child_process";

const router = Router();

router.post("/command", (req, res) => {
  exec(req.body.command);
  res.sendStatus(202);
});

export default router;
