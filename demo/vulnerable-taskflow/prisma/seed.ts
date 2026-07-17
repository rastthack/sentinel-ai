import { createPrismaClient } from "../src/db.js";
import { resetDatabase } from "../src/db/seed-data.js";

const prisma = createPrismaClient();

resetDatabase(prisma)
  .then(() => console.log("TaskFlow AI demo data seeded"))
  .finally(() => prisma.$disconnect());
