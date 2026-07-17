"""Focused Prisma schema parser tests."""

from sentinel_api.scanner.discovery.prisma_schema import PrismaSchemaParser
from sentinel_api.scanner.models import IndexResult


def test_models_relations_constraints_and_ownership_candidates_are_parsed() -> None:
    index = IndexResult(
        contents={
            "prisma/schema.prisma": """
                datasource db { provider = "sqlite" }
                generator client {
                  provider = "prisma-client-js"
                  output = "../generated"
                }
                enum Status { ACTIVE ARCHIVED }
                model User {
                  id String @id
                  email String @unique
                  projects Project[]
                }
                model Project {
                  id String @id
                  ownerId String
                  owner User @relation(fields: [ownerId], references: [id])
                  status Status @default(ACTIVE)
                  note String?
                  @@unique([id, ownerId])
                  @@index([ownerId])
                }
            """
        }
    )

    data_model, warnings = PrismaSchemaParser().parse(index)

    assert warnings == []
    assert data_model.provider == "sqlite"
    assert data_model.generators[0].output == "../generated"
    project = next(model for model in data_model.models if model.name == "Project")
    fields = {field.name: field for field in project.fields}
    assert fields["ownerId"].is_foreign_key
    assert fields["ownerId"].relation_model == "User"
    assert fields["owner"].is_relation_field
    assert fields["status"].is_enum
    assert fields["note"].is_optional
    user = next(model for model in data_model.models if model.name == "User")
    assert next(field for field in user.fields if field.name == "projects").is_list
    assert project.unique_fields == ["id", "ownerId"]
    assert [(item.model, item.field) for item in data_model.ownership_candidates] == [
        ("Project", "ownerId")
    ]
