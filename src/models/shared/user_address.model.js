const { sequelize, DataTypes, Model } = require('../../config/database');

class UserAddress extends Model {}

UserAddress.init({
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true
    },
    userID: {
        type: DataTypes.UUID,
        allowNull: false,
        references: {
            model: 'user',
            key: 'id',
        },
        onUpdate: 'CASCADE',
        onDelete: 'CASCADE'
    },
    address_type: {
        type: DataTypes.ENUM('shipping', 'billing', 'both'),
        allowNull: false,
        defaultValue: 'both'
    }
}, {
    sequelize,
    tableName: 'user_address',
    underscored: true,
    timestamps: true,
    updatedAt: 'updated_at'
});

module.exports = { UserAddress };
