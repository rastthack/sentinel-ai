import { Router } from "express";

export const healthRouter = Router();

healthRouter.get("/health", (_request, response) => {
  response.json({ service: "taskflow-ai", status: "ok", version: "1.0.0" });
});
