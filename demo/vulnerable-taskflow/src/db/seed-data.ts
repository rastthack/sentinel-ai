import type { PrismaClient } from "../generated/prisma/client.js";

export const demo = Object.freeze({
  userA: { id: "user-a", email: "user_a@example.test", token: "user-a-demo-token" },
  userB: { id: "user-b", email: "user_b@example.test", token: "user-b-demo-token" },
  projectA: { id: "project-a" },
  projectB: { id: "project-b" },
});

export async function resetDatabase(prisma: PrismaClient): Promise<void> {
  await prisma.$transaction([
    prisma.task.deleteMany(),
    prisma.projectMember.deleteMany(),
    prisma.project.deleteMany(),
    prisma.user.deleteMany(),
  ]);

  await prisma.user.create({
    data: {
      id: demo.userA.id,
      email: demo.userA.email,
      demoToken: demo.userA.token,
      name: "Avery Chen",
      title: "Product Lead",
      ownedProjects: {
        create: {
          id: demo.projectA.id,
          name: "Launch Command Center",
          description: "Coordinate the public launch across product, marketing, and support.",
          status: "ACTIVE",
          members: { create: { id: "member-a-project-a", userId: demo.userA.id, role: "OWNER" } },
          tasks: {
            create: [
              {
                id: "task-a-1",
                title: "Finalize launch checklist",
                description: "Confirm owners and exit criteria for every launch workstream.",
                status: "IN_PROGRESS",
                priority: "HIGH",
                assigneeId: demo.userA.id,
                dueDate: new Date("2026-08-05T12:00:00.000Z"),
              },
              {
                id: "task-a-2",
                title: "Review release notes",
                description: "Check customer-facing messaging and known limitations.",
                status: "TODO",
                priority: "MEDIUM",
                assigneeId: demo.userA.id,
                dueDate: new Date("2026-08-08T12:00:00.000Z"),
              },
            ],
          },
        },
      },
    },
  });

  await prisma.user.create({
    data: {
      id: demo.userB.id,
      email: demo.userB.email,
      demoToken: demo.userB.token,
      name: "Blake Morgan",
      title: "Engineering Manager",
      ownedProjects: {
        create: {
          id: demo.projectB.id,
          name: "Platform Reliability",
          description: "Improve service resilience and reduce incident response time.",
          status: "AT_RISK",
          members: { create: { id: "member-b-project-b", userId: demo.userB.id, role: "OWNER" } },
          tasks: {
            create: [
              {
                id: "task-b-1",
                title: "Define service objectives",
                description: "Publish latency and availability targets for critical APIs.",
                status: "DONE",
                priority: "HIGH",
                assigneeId: demo.userB.id,
                dueDate: new Date("2026-07-30T12:00:00.000Z"),
              },
              {
                id: "task-b-2",
                title: "Run failover exercise",
                description: "Validate the regional recovery runbook in staging.",
                status: "TODO",
                priority: "CRITICAL",
                assigneeId: demo.userB.id,
                dueDate: new Date("2026-08-12T12:00:00.000Z"),
              },
            ],
          },
        },
      },
    },
  });
}
