const { sequelize } = require("../src/config/database.config");
const models = require("../src/models");

/**
 * Synchronize database schema with Sequelize models.
 *
 * Modes:
 *   (default)  Create new tables only — existing tables are untouched
 *   --alter    ALTER each table to match model (safe, per-model error handling)
 *   --force    DROP all tables and recreate (loses all data)
 *
 * npm scripts:
 *   npm run db:sync           --force
 *   npm run db:sync:safe      --alter
 *   npm run db:sync:create    default
 */
const syncDatabase = async () => {
  const force = process.argv.includes("--force");
  const alter = process.argv.includes("--alter");

  try {
    if (force) {
      console.log(
        "WARNING: --force will DROP ALL TABLES and recreate them. All data will be lost.\n",
      );
      await sequelize.sync({ force: true });
      console.log("Database synchronized (force).");
      return;
    }

    const modelList = Object.values(sequelize.models);
    const failed = [];

    if (alter) {
      console.log("Syncing each model with alter...\n");
      for (const model of modelList) {
        try {
          await model.sync({ alter: true });
          console.log(`  OK  ${model.name}`);
        } catch (err) {
          failed.push(model.name);
          console.log(`  FAIL  ${model.name}: ${err.message}`);
        }
      }
    } else {
      console.log("Creating new tables only (existing tables unchanged)...\n");
      for (const model of modelList) {
        try {
          await model.sync();
          console.log(`  OK  ${model.name}`);
        } catch (err) {
          failed.push(model.name);
          console.log(`  WARN  ${model.name}: ${err.message}`);
        }
      }
    }

    console.log(
      `\nDone. ${modelList.length - failed.length}/${modelList.length} models synced.`,
    );
    if (failed.length > 0) {
      console.log(`Failed: ${failed.join(", ")}`);
    }

    process.exit(0);
  } catch (error) {
    console.error("Fatal error during sync:", error.message);
    process.exit(1);
  }
};

syncDatabase();
