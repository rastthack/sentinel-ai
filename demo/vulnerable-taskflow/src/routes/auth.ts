import type { PrismaClient } from "../generated/prisma/client.js";
import { Router } from "express";

type LoginBody = { email?: unknown; token?: unknown };

export function createAuthRouter(prisma: PrismaClient): Router {
  const router = Router();

  router.post("/login", async (request, response) => {
    const { email, token } = request.body as LoginBody;
    if (
      typeof email !== "string" ||
      email.length > 254 ||
      typeof token !== "string" ||
      token.length > 128
    ) {
      response.status(400).json({ error: "A valid email and demo token are required" });
      return;
    }

    const user = await prisma.user.findUnique({
      where: { demoToken: token },
      select: { id: true, email: true, name: true, title: true, demoToken: true },
    });

    if (!user || user.email !== email.trim().toLowerCase()) {
      response.status(401).json({ error: "Invalid demo credentials" });
      return;
    }

    response.json({
      token: user.demoToken,
      tokenType: "Bearer",
      user: { id: user.id, email: user.email, name: user.name, title: user.title },
    });
  });

  return router;
}
