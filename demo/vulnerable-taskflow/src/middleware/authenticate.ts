import type { NextFunction, Request, Response } from "express";
import type { PrismaClient } from "../generated/prisma/client.js";

export function authenticate(prisma: PrismaClient) {
  return async (request: Request, response: Response, next: NextFunction): Promise<void> => {
    const authorization = request.header("authorization");
    const [scheme, token] = authorization?.split(" ") ?? [];

    if (scheme !== "Bearer" || !token) {
      response.status(401).json({ error: "A valid Bearer token is required" });
      return;
    }

    const user = await prisma.user.findUnique({
      where: { demoToken: token },
      select: { id: true, email: true, name: true },
    });

    if (!user) {
      response.status(401).json({ error: "A valid Bearer token is required" });
      return;
    }

    request.authUser = user;
    next();
  };
}
