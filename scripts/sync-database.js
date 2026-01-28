const { sequelize } = require('../src/config/database');
const models = require('../src/models');

/**
 * Script to synchronize database schema with Sequelize models
 * 
 * Usage:
 * - Development: npm run db:sync (drops all tables and recreates)
 * - Production: npm run db:sync:safe (only adds new tables/columns)
 */

const syncDatabase = async () => {
    try {
        const force = process.argv.includes('--force');
        const alter = process.argv.includes('--alter');
        
        console.log('🔄 Starting database synchronization...\n');
        
        if (force) {
            console.log('⚠️  WARNING: --force flag detected');
            console.log('⚠️  This will DROP ALL TABLES and recreate them!');
            console.log('⚠️  All data will be LOST!\n');
            
            await sequelize.sync({ force: true });
            console.log('✅ Database synchronized with force=true (all tables dropped and recreated)');
        } else if (alter) {
            console.log('🔧 Using --alter flag (safe mode)');
            console.log('🔧 This will modify existing tables to match models\n');
            
            await sequelize.sync({ alter: true });
            console.log('✅ Database synchronized with alter=true (tables modified safely)');
        } else {
            console.log('📋 Default mode: Creating new tables only');
            console.log('📋 Existing tables will not be modified\n');
            
            await sequelize.sync();
            console.log('✅ Database synchronized successfully');
        }
        
        console.log('\n📊 Models synchronized:');
        Object.keys(sequelize.models).forEach(modelName => {
            console.log(`   - ${modelName}`);
        });
        
        console.log('\n✅ All done!');
        process.exit(0);
        
    } catch (error) {
        console.error('❌ Error synchronizing database:', error);
        process.exit(1);
    }
};

syncDatabase();
