/**
 * Intentionally missing rate limiting.
 * Scanner validation only.
 */

import { Router } from "express";

const router = Router();

function loginHandler(_req: unknown, _res: unknown) {
  return;
}

router.post("/login", loginHandler);

export default router;
