import type { ErrorRequestHandler, RequestHandler } from "express";

export const notFound: RequestHandler = (_request, response) => {
  response.status(404).json({ error: "Route not found" });
};

export const handleError: ErrorRequestHandler = (error: unknown, _request, response, _next) => {
  const message = error instanceof Error ? error.message : "Unknown error";
  console.error("Request failed", { message });
  response.status(500).json({ error: "Internal server error" });
};
