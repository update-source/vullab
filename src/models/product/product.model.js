const { sequelize, DataTypes, Model } = require('../../config/database');

class Product extends Model { }

Product.init({
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true
    },
    name: {
        type: DataTypes.STRING(255),
        allowNull: false
    },
    description: {
        type: DataTypes.TEXT
    },
    categoryId: {
        type: DataTypes.UUID,
        allowNull: false,
        references: {
            model: 'category',
            key: 'id'
        }
    },
    sku: {
        type: DataTypes.STRING(50),
        allowNull: false,
        unique: true
    },
    productImage: {
        type: DataTypes.STRING(255)
    },
    isPublished: {
        type: DataTypes.BOOLEAN,
        defaultValue: true // IDOR lab
    }
}, {
    sequelize,
    tableName: 'product',
    underscored: true,
    timestamps: true
});

module.exports = { Product };