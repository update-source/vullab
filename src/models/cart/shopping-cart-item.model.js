const { sequelize, DataTypes, Model } = require('../../config/database');

class ShoppingCartItem extends Model { }

ShoppingCartItem.init({
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true
    },
    cartId: {
        type: DataTypes.UUID,
        allowNull: false,
        references: {
            model: 'shopping_cart',
            key: 'id'
        }
    },
    productItemId: {
        type: DataTypes.UUID,
        allowNull: false,
        references: {
            model: 'product_item',
            key: 'id'
        }
    },
    quantity: {
        type: DataTypes.INTEGER,
        defaultValue: 1,
        allowNull: false,
        validate: {
            min: 1
        }
    }
}, {
    sequelize,
    tableName: 'shopping_cart_item',
    underscored: true,
    timestamps: true,
    indexes: [
        {
            unique: true,
            fields: ['cart_id', 'product_item_id']
        }
    ]
});

module.exports = { ShoppingCartItem };
