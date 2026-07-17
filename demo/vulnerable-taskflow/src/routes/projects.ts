import type { PrismaClient } from "../generated/prisma/client.js";
import { Router } from "express";

function currentUserId(user: Express.Request["authUser"]): string {
  if (!user) throw new Error("Authentication middleware invariant failed");
  return user.id;
}

export function createProjectsRouter(prisma: PrismaClient): Router {
  const router = Router();

  router.get("/", async (request, response) => {
    const projects = await prisma.project.findMany({
      where: { ownerId: currentUserId(request.authUser) },
      include: { _count: { select: { members: true, tasks: true } } },
      orderBy: { createdAt: "asc" },
    });
    response.json({ projects });
  });

  router.get("/:id", async (request, response) => {
    // INTENTIONALLY VULNERABLE (BOLA): authentication is enforced by the parent
    // router, but this lookup deliberately omits `ownerId`. Sentinel AI will use
    // this single isolated flaw in a later milestone. Do not copy this pattern.
    const project = await prisma.project.findUnique({
      where: { id: request.params.id },
      include: {
        owner: { select: { id: true, email: true, name: true } },
        members: {
          include: { user: { select: { id: true, email: true, name: true } } },
          orderBy: { joinedAt: "asc" },
        },
        tasks: { orderBy: { createdAt: "asc" } },
      },
    });

    if (!project) {
      response.status(404).json({ error: "Project not found" });
      return;
    }

    response.json({ project });
  });

  return router;
}
