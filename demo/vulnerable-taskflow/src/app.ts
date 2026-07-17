import express, { type Express } from "express";
import helmet from "helmet";

import { prisma as defaultPrisma } from "./db.js";
import type { PrismaClient } from "./generated/prisma/client.js";
import { authenticate } from "./middleware/authenticate.js";
import { handleError, notFound } from "./middleware/errors.js";
import { createAuthRouter } from "./routes/auth.js";
import { createDashboardRouter } from "./routes/dashboard.js";
import { healthRouter } from "./routes/health.js";
import { createProfileRouter } from "./routes/profile.js";
import { createProjectsRouter } from "./routes/projects.js";
import { createTasksRouter } from "./routes/tasks.js";

export function createApp(prisma: PrismaClient = defaultPrisma): Express {
  const app = express();

  app.disable("x-powered-by");
  app.use(helmet());
  app.use(express.json({ limit: "16kb", strict: true }));

  app.use(healthRouter);
  app.use("/api", createAuthRouter(prisma));

  const protectedApi = express.Router();
  protectedApi.use(authenticate(prisma));
  protectedApi.use("/dashboard", createDashboardRouter(prisma));
  protectedApi.use("/projects", createProjectsRouter(prisma));
  protectedApi.use("/tasks", createTasksRouter(prisma));
  protectedApi.use("/profile", createProfileRouter(prisma));
  app.use("/api", protectedApi);

  app.use(notFound);
  app.use(handleError);
  return app;
}
