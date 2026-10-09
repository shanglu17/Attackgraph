import "dotenv/config";

const configuredNeo4jUri = process.env.NEO4J_URI ?? "bolt://127.0.0.1:7687";
const neo4jUri = configuredNeo4jUri.replace(
  /^(bolt(?:\+s|\+ssc)?|neo4j(?:\+s|\+ssc)?):\/\/localhost(?=[:/]|$)/i,
  "$1://127.0.0.1",
);

export const env = {
  port: Number(process.env.PORT ?? 4000),
  // Docker Desktop on Windows can publish Bolt on IPv4 while localhost resolves to ::1.
  neo4jUri,
  neo4jUsername: process.env.NEO4J_USERNAME ?? "neo4j",
  neo4jPassword: process.env.NEO4J_PASSWORD ?? "change-me"
};
