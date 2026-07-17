import { createApp } from "./app.js";
import { config } from "./config.js";
import { prisma } from "./db.js";

const app = createApp(prisma);
const server = app.listen(config.port, config.host, () => {
  console.log(`TaskFlow AI listening on http://${config.host}:${String(config.port)}`);
});

function shutdown(signal: string): void {
  console.log(`${signal} received; shutting down`);
  server.close(() => {
    void prisma.$disconnect().finally(() => process.exit(0));
  });
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
