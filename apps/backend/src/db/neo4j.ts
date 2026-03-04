import neo4j, { Driver } from "neo4j-driver";
import { env } from "../config/env.js";

let driver: Driver | null = null;

export const getDriver = (): Driver => {
  if (!driver) {
    driver = neo4j.driver(env.neo4jUri, neo4j.auth.basic(env.neo4jUsername, env.neo4jPassword));
  }
  return driver;
};

export const closeDriver = async (): Promise<void> => {
  if (driver) {
    await driver.close();
    driver = null;
  }
};
