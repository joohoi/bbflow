CREATE TABLE "projects" (
  "id" INT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  "name" varchar UNIQUE
);

CREATE TABLE "domains" (
  "id" INT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  "name" varchar UNIQUE,
  "sources" varchar,
  "project_id" int
);

CREATE TABLE "hosts" (
  "id" INT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  "address" varchar UNIQUE,
  "family" varchar
);

CREATE TABLE "ports" (
  "id" INT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  "host_id" int,
  "number" int,
  "protocol" varchar,
  "service" varchar,
  "product" varchar,
  "version" varchar
);

CREATE TABLE "domains_hosts" (
  "id" INT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  "domains_id" int,
  "hosts_id" int
);

CREATE TABLE "webs" (
  "id" INT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  "url" varchar,
  "domain_id" int,
  "port_id" int,
  "response" varchar
);

ALTER TABLE "domains" ADD FOREIGN KEY ("project_id") REFERENCES "projects" ("id");

ALTER TABLE "ports" ADD FOREIGN KEY ("host_id") REFERENCES "hosts" ("id");

ALTER TABLE "domains_hosts" ADD FOREIGN KEY ("domains_id") REFERENCES "domains" ("id");

ALTER TABLE "domains_hosts" ADD FOREIGN KEY ("hosts_id") REFERENCES "hosts" ("id");

ALTER TABLE "webs" ADD FOREIGN KEY ("domain_id") REFERENCES "domains" ("id");

ALTER TABLE "webs" ADD FOREIGN KEY ("port_id") REFERENCES "ports" ("id");