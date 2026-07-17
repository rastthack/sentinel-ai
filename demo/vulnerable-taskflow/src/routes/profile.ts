import type { PrismaClient } from "../generated/prisma/client.js";
import { Router } from "express";

export function createProfileRouter(prisma: PrismaClient): Router {
  const router = Router();

  router.get("/", async (request, response) => {
    if (!request.authUser) throw new Error("Authentication middleware invariant failed");

    const profile = await prisma.user.findUnique({
      where: { id: request.authUser.id },
      select: {
        id: true,
        email: true,
        name: true,
        title: true,
        createdAt: true,
        _count: { select: { assignedTasks: true, memberships: true, ownedProjects: true } },
      },
    });
    response.json({ profile });
  });

  return router;
}
