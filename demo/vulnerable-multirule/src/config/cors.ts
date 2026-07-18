/**
 * Intentionally dangerous CORS configuration.
 * Scanner validation only.
 */

import cors from "cors";

export const insecureCors = cors({
  origin: "*",
  credentials: true
});
