import type { PrismaClient } from "../generated/prisma/client.js";
import { Router } from "express";

export function createDashboardRouter(prisma: PrismaClient): Router {
  const router = Router();

  router.get("/", async (request, response) => {
    if (!request.authUser) throw new Error("Authentication middleware invariant failed");

    const ownerId = request.authUser.id;
    const ownedProjectFilter = { project: { ownerId } };
    const [projectCount, taskCount, completedTaskCount, atRiskProjectCount, recentProjects] =
      await Promise.all([
        prisma.project.count({ where: { ownerId } }),
        prisma.task.count({ where: ownedProjectFilter }),
        prisma.task.count({ where: { ...ownedProjectFilter, status: "DONE" } }),
        prisma.project.count({ where: { ownerId, status: "AT_RISK" } }),
        prisma.project.findMany({
          where: { ownerId },
          select: { id: true, name: true, status: true, updatedAt: true },
          orderBy: { updatedAt: "desc" },
          take: 5,
        }),
      ]);

    response.json({
      dashboard: {
        projectCount,
        taskCount,
        completedTaskCount,
        atRiskProjectCount,
        recentProjects,
      },
    });
  });

  return router;
}
