/**
 * Intentionally vulnerable multi-rule fixture.
 * Local scanner validation only.
 */

import express from "express";
import { insecureCors } from "./config/cors";
import "./config/tokens";
import authRoutes from "./routes/auth";
import redirectRoutes from "./routes/redirect";
import fileRoutes from "./routes/files";
import commandRoutes from "./routes/command";
import uploadRoutes from "./routes/upload";

const app = express();

app.use(express.json());
app.use(insecureCors);

app.use(authRoutes);
app.use(redirectRoutes);
app.use(fileRoutes);
app.use(commandRoutes);
app.use(uploadRoutes);

export default app;
