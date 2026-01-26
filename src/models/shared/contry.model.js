const { sequelize, DataTypes, Model } = require('../../config/database');

class Contry extends Model {}

Contry.init({
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true
    },
    contryName: {
        type: DataTypes.STRING(100),
        allowNull: false
    },
    contryCode: {
        type: DataTypes.STRING(10),
        allowNull: false
    }
}, {
    sequelize,
    tableName: 'country',
    underscored: true
});

module.exports = { Contry };