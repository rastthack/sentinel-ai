import "dotenv/config";

import { createPrismaClient } from "../src/db.js";

const databaseUrl = process.env.DATABASE_URL ?? "file:./dev.db";
if (!databaseUrl.startsWith("file:")) {
  throw new Error("TaskFlow AI migrations require a local SQLite file URL");
}

const prisma = createPrismaClient(databaseUrl);
await prisma.$connect();
await prisma.$disconnect();
