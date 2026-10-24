export type AppEnv = "development" | "staging" | "production";

export interface AppConfig {
  appEnv: AppEnv;
  port: number;
  dataDir: string;
  scheduleEnabled: boolean;
}

const ALLOWED_APP_ENVS: readonly AppEnv[] = ["development", "staging", "production"];

function isAppEnv(value: string): value is AppEnv {
  return (ALLOWED_APP_ENVS as readonly string[]).includes(value);
}

export function loadConfig(env: Record<string, string | undefined> = process.env): AppConfig {
  const appEnvRaw = env.APP_ENV;
  if (appEnvRaw === undefined || appEnvRaw === "") {
    throw new Error("Missing required env var APP_ENV. Set APP_ENV to one of: development, staging, production.");
  }
  if (!isAppEnv(appEnvRaw)) {
    throw new Error(
      `Invalid APP_ENV "${appEnvRaw}". Expected one of: development, staging, production.`,
    );
  }

  const portRaw = env.PORT;
  if (portRaw === undefined || portRaw === "") {
    throw new Error("Missing required env var PORT. Set PORT to a TCP port number, e.g. 3000.");
  }
  const port = Number(portRaw);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`Invalid PORT "${portRaw}". Expected an integer between 1 and 65535.`);
  }

  const dataDir = env.DATA_DIR;
  if (dataDir === undefined || dataDir === "") {
    throw new Error("Missing required env var DATA_DIR. Set DATA_DIR to the local data directory path.");
  }

  const scheduleRaw = env.SCHEDULE_ENABLED;
  if (scheduleRaw === undefined || scheduleRaw === "") {
    throw new Error("Missing required env var SCHEDULE_ENABLED. Set SCHEDULE_ENABLED to true or false.");
  }
  if (scheduleRaw !== "true" && scheduleRaw !== "false") {
    throw new Error(`Invalid SCHEDULE_ENABLED "${scheduleRaw}". Expected true or false.`);
  }

  return {
    appEnv: appEnvRaw,
    port,
    dataDir,
    scheduleEnabled: scheduleRaw === "true",
  };
}
