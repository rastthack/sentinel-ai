import "dotenv/config";

function parsePort(value: string | undefined): number {
  const port = Number(value ?? "4000");
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error("PORT must be an integer between 1 and 65535");
  }
  return port;
}

export const config = Object.freeze({
  host: process.env.HOST ?? "127.0.0.1",
  port: parsePort(process.env.PORT),
  nodeEnv: process.env.NODE_ENV ?? "development",
});
