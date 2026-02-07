const { sequelize, DataTypes, Model } = require('../../config/database.config');

class UserSecurityLog extends Model {}

UserSecurityLog.init({
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true
    },
    userId: {
        type: DataTypes.UUID,
        allowNull: true, // Allow null to track failed attempts for non-existing usernames
        references: {
            model: 'user',
            key: 'id'
        }
    },
    eventType: {
        type: DataTypes.ENUM('login_success', 'login_failed', 'password_changed'),
        allowNull: false
    },
    ipAddress: {
        type: DataTypes.STRING(45)
    },
    userAgent: {
        type: DataTypes.TEXT
    },
    metadata: {
        type: DataTypes.JSONB,
        defaultValue: {}
    } 
}, {
    sequelize,
    tableName: 'user_security_log',
    underscored: true,
    timestamps: true
});

module.exports = { UserSecurityLog };