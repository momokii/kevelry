// Hermetic test seed: the suite must pass on a bare shell with no ambient
// config, so the four variables the shell reads are seeded here with explicit
// placeholder values. Assignment is unconditional so results are identical
// under any ambient env. Fail-closed behavior is proven by the
// explicit-deletion negative test in tests/config.test.ts, not by ambient
// absence.
process.env.APP_ENV = "development";
process.env.PORT = "3000";
process.env.DATA_DIR = "./data";
process.env.SCHEDULE_ENABLED = "false";
