const { sequelize } = require('../src/config/database.config');
const models = require('../src/models');

/**
 * Script to synchronize database schema with Sequelize models.
 *
 * Modes:
 *   --force   : DROP all tables and recreate (loses all data!)
 *   --alter   : Try to ALTER each table to match model (safe, per-model error handling)
 *   (default) : CREATE new tables only — existing tables are untouched
 *
 * Usage:
 *   node scripts/sync-database.js           → create new tables only
 *   node scripts/sync-database.js --alter   → alter existing tables (npm run db:sync:safe)
 *   node scripts/sync-database.js --force   → drop & recreate all  (npm run db:sync)
 *
 * npm scripts:
 *   npm run db:sync        → --force
 *   npm run db:sync:safe   → --alter
 *   npm run db:sync:create → default (create only)
 *
 * Integrated with npm run dev via "predev" hook — runs default mode automatically.
 */

const syncDatabase = async () => {
    const force = process.argv.includes('--force');
    const alter = process.argv.includes('--alter');

    try {
        console.log('🔄 Starting database synchronization...\n');

        if (force) {
            console.log('⚠️  WARNING: --force flag detected');
            console.log('⚠️  This will DROP ALL TABLES and recreate them!');
            console.log('⚠️  All data will be LOST!\n');
            await sequelize.sync({ force: true });
            console.log('✅ Database synchronized with force=true\n');
        } else if (alter) {
            console.log('🔧 --alter mode: syncing each model individually...\n');

            const modelList = Object.values(sequelize.models);
            const results = { success: [], failed: [] };

            for (const model of modelList) {
                try {
                    await model.sync({ alter: true });
                    results.success.push(model.name);
                    process.stdout.write(`   ✅ ${model.name}\n`);
                } catch (err) {
                    results.failed.push({ name: model.name, error: err.message });
                    process.stdout.write(`   ❌ ${model.name}: ${err.message}\n`);
                }
            }

            console.log('\n📊 Results:');
            console.log(`   ✅ Synced:  ${results.success.length} models`);
            if (results.failed.length > 0) {
                console.log(`   ❌ Failed:  ${results.failed.length} models (see above)`);
                console.log('\n💡 Tip: Failed models may need manual ALTER or --force to fix.');
            }
        } else {
            // Default: create new tables only — safe, never modifies existing columns
            console.log('📋 Default mode: Creating new tables only');
            console.log('📋 Existing tables will NOT be modified\n');

            const modelList = Object.values(sequelize.models);
            const results = { created: [], existing: [] };

            for (const model of modelList) {
                try {
                    // sync() without options only creates if not exists
                    await model.sync();
                    results.created.push(model.name);
                    process.stdout.write(`   ✅ ${model.name}\n`);
                } catch (err) {
                    results.existing.push({ name: model.name, error: err.message });
                    process.stdout.write(`   ⚠️  ${model.name}: ${err.message}\n`);
                }
            }

            console.log(`\n📊 Synced ${results.created.length} models`);
            if (results.existing.length > 0) {
                console.log(`   ⚠️  ${results.existing.length} models had warnings`);
            }
        }

        console.log('\n✅ All done!');
        process.exit(0);

    } catch (error) {
        console.error('\n❌ Fatal error during sync:', error.message);
        process.exit(1);
    }
};

syncDatabase();
