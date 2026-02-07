const { sequelize, DataTypes, Model } = require('../../config/database.config');

class Address extends Model {} 

Address.init({
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true
    },
    streetAddress: {
        type: DataTypes.STRING(255),
        allowNull: false
    },
    streetAddress2: {
        type: DataTypes.STRING(255),
    },
    city: {
        type: DataTypes.STRING(100),
        allowNull: false
    },
    stateProvince: {
        type: DataTypes.STRING(100),
    },
    postalCode: {
        type: DataTypes.STRING(20),
        allowNull: false
    },
    countryId: {
        type: DataTypes.UUID,
        allowNull: false,
        references: {
            model: 'country',
            key: 'id',
        }
    }
}, { 
    sequelize,
    tableName: 'address',
    underscored: true,
    timestamps: true
});

module.exports = { Address };