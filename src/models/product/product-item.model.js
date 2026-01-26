const { sequelize, DataTypes, Model } = require('../../config/database');

class ProductItem extends Model { }

ProductItem.init({
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true
    },
    productId: {
        type: DataTypes.UUID,
        allowNull: false,
        references: {
            model: 'product',
            key: 'id'
        }
    },
    sku: {
        type: DataTypes.STRING(50),
        allowNull: false,
        unique: true
    },
    price: {
        type: DataTypes.DECIMAL(10, 2),
        allowNull: false
    },
    originalPrice: {
        type: DataTypes.DECIMAL(10, 2)
    },
    quantityInStock: {
        type: DataTypes.INTEGER,
        defaultValue: 0,
        allowNull: false
    },
    productImage: {
        type: DataTypes.STRING(255)
    },
    isActive: {
        type: DataTypes.BOOLEAN,
        defaultValue: true
    }
}, {
    sequelize,
    tableName: 'product_item',
    underscored: true,
    timestamps: true
});

module.exports = { ProductItem };
