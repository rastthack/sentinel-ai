/**
 * Intentionally vulnerable open redirect.
 * Scanner validation only.
 */

import { Router } from "express";

const router = Router();

router.get("/continue", (req, res) => {
  res.redirect(req.query.next as string);
});

export default router;
