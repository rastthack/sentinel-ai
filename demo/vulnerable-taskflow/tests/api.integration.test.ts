import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createApp } from "../src/app.js";
import { createPrismaClient } from "../src/db.js";
import { demo, resetDatabase } from "../src/db/seed-data.js";

const prisma = createPrismaClient(process.env.DATABASE_URL ?? "file:./test.db");
const app = createApp(prisma);

function bearer(token: string): { Authorization: string } {
  return { Authorization: `Bearer ${token}` };
}

beforeAll(async () => {
  await resetDatabase(prisma);
});

afterAll(async () => {
  await prisma.$disconnect();
});

describe("TaskFlow AI API", () => {
  it("reports service health", async () => {
    const response = await request(app).get("/health").expect(200);
    expect(response.body).toEqual({ service: "taskflow-ai", status: "ok", version: "1.0.0" });
  });

  it("requires authentication for protected endpoints", async () => {
    const response = await request(app).get("/api/projects").expect(401);
    expect(response.body).toEqual({ error: "A valid Bearer token is required" });
  });

  it("logs in a demo user", async () => {
    const response = await request(app)
      .post("/api/login")
      .send({ email: demo.userA.email, token: demo.userA.token })
      .expect(200);
    expect(response.body.token).toBe(demo.userA.token);
    expect(response.body.user.id).toBe(demo.userA.id);
  });

  it("rejects an invalid demo login", async () => {
    const response = await request(app)
      .post("/api/login")
      .send({ email: demo.userA.email, token: "not-a-valid-token" })
      .expect(401);
    expect(response.body).toEqual({ error: "Invalid demo credentials" });
  });

  it("User A only lists projects owned by User A", async () => {
    const response = await request(app)
      .get("/api/projects")
      .set(bearer(demo.userA.token))
      .expect(200);
    expect(response.body.projects.map((project: { id: string }) => project.id)).toEqual([
      demo.projectA.id,
    ]);
  });

  it("User B only lists projects owned by User B", async () => {
    const response = await request(app)
      .get("/api/projects")
      .set(bearer(demo.userB.token))
      .expect(200);
    expect(response.body.projects.map((project: { id: string }) => project.id)).toEqual([
      demo.projectB.id,
    ]);
  });

  it("scopes User A's dashboard aggregates to User A", async () => {
    const response = await request(app)
      .get("/api/dashboard")
      .set(bearer(demo.userA.token))
      .expect(200);
    expect(response.body.dashboard).toMatchObject({
      projectCount: 1,
      taskCount: 2,
      completedTaskCount: 0,
      atRiskProjectCount: 0,
    });
    expect(response.body.dashboard.recentProjects.map((project: { id: string }) => project.id)).toEqual([
      demo.projectA.id,
    ]);
  });

  it("User A only lists tasks from projects owned by User A", async () => {
    const response = await request(app)
      .get("/api/tasks")
      .set(bearer(demo.userA.token))
      .expect(200);
    expect(response.body.tasks.map((task: { id: string }) => task.id)).toEqual([
      "task-a-1",
      "task-a-2",
    ]);
  });

  it("User B only lists tasks from projects owned by User B", async () => {
    const response = await request(app)
      .get("/api/tasks")
      .set(bearer(demo.userB.token))
      .expect(200);
    expect(response.body.tasks.map((task: { id: string }) => task.id)).toEqual([
      "task-b-1",
      "task-b-2",
    ]);
  });

  it("returns the authenticated user's profile without its Bearer token", async () => {
    const response = await request(app)
      .get("/api/profile")
      .set(bearer(demo.userA.token))
      .expect(200);
    expect(response.body.profile.id).toBe(demo.userA.id);
    expect(response.body.profile).not.toHaveProperty("demoToken");
  });

  it("User A accesses Project A", async () => {
    const response = await request(app)
      .get(`/api/projects/${demo.projectA.id}`)
      .set(bearer(demo.userA.token))
      .expect(200);
    expect(response.body.project.ownerId).toBe(demo.userA.id);
  });

  it("User B accesses Project B", async () => {
    const response = await request(app)
      .get(`/api/projects/${demo.projectB.id}`)
      .set(bearer(demo.userB.token))
      .expect(200);
    expect(response.body.project.ownerId).toBe(demo.userB.id);
  });

  it("INTENTIONAL BOLA: User A incorrectly accesses Project B", async () => {
    const response = await request(app)
      .get(`/api/projects/${demo.projectB.id}`)
      .set(bearer(demo.userA.token))
      .expect(200);
    expect(response.body.project.ownerId).toBe(demo.userB.id);
  });

  it("INTENTIONAL BOLA: User B incorrectly accesses Project A", async () => {
    const response = await request(app)
      .get(`/api/projects/${demo.projectA.id}`)
      .set(bearer(demo.userB.token))
      .expect(200);
    expect(response.body.project.ownerId).toBe(demo.userA.id);
  });

  it("returns 404 for an unknown project", async () => {
    const response = await request(app)
      .get("/api/projects/project-does-not-exist")
      .set(bearer(demo.userA.token))
      .expect(404);
    expect(response.body).toEqual({ error: "Project not found" });
  });
});
