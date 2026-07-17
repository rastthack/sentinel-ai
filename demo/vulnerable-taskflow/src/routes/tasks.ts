import type { PrismaClient } from "../generated/prisma/client.js";
import { Router } from "express";

export function createTasksRouter(prisma: PrismaClient): Router {
  const router = Router();

  router.get("/", async (request, response) => {
    if (!request.authUser) throw new Error("Authentication middleware invariant failed");

    const tasks = await prisma.task.findMany({
      where: { project: { ownerId: request.authUser.id } },
      include: {
        project: { select: { id: true, name: true } },
        assignee: { select: { id: true, name: true } },
      },
      orderBy: [{ dueDate: "asc" }, { createdAt: "asc" }],
    });
    response.json({ tasks });
  });

  return router;
}
