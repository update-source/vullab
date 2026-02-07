const { sequelize, DataTypes, Model } = require('../../config/database.config');

class PromotionCategory extends Model { }

PromotionCategory.init({
    promotionId: {
        type: DataTypes.UUID,
        allowNull: false,
        primaryKey: true,
        references: {
            model: 'promotion',
            key: 'id'
        }
    },
    categoryId: {
        type: DataTypes.UUID,
        allowNull: false,
        primaryKey: true,
        references: {
            model: 'category',
            key: 'id'
        }
    }
}, {
    sequelize,
    tableName: 'promotion_category',
    underscored: true,
    timestamps: false
});

module.exports = { PromotionCategory };
