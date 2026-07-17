import "dotenv/config";

import { createPrismaClient } from "../src/db.js";
import { resetDatabase } from "../src/db/seed-data.js";

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl?.startsWith("file:")) {
  throw new Error("Refusing to reset: DATABASE_URL must point to a local SQLite file");
}

const prisma = createPrismaClient(databaseUrl);

resetDatabase(prisma)
  .then(() => console.log("TaskFlow AI database reset and seeded"))
  .finally(() => prisma.$disconnect());
