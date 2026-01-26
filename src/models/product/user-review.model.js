const { sequelize, DataTypes, Model } = require('../../config/database');

class UserReview extends Model { }

UserReview.init({
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true
    },
    userId: {
        type: DataTypes.UUID,
        allowNull: false,
        references: {
            model: 'user',
            key: 'id'
        }
    },
    productId: {
        type: DataTypes.UUID,
        allowNull: false,
        references: {
            model: 'product',
            key: 'id'
        }
    },
    orderId: {
        type: DataTypes.UUID,
        allowNull: true,
        // references: { model: 'shop_order', key: 'id' } // Will enable after Order module is created
    },
    rating: {
        type: DataTypes.INTEGER,
        allowNull: false,
        validate: {
            min: 1,
            max: 5
        }
    },
    title: {
        type: DataTypes.STRING(200)
    },
    comment: {
        type: DataTypes.TEXT,
        // CRITICAL for XSS labs
    },
    isVerifiedPurchase: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
    },
    isApproved: {
        type: DataTypes.BOOLEAN,
        defaultValue: true
    },
    helpfulCount: {
        type: DataTypes.INTEGER,
        defaultValue: 0
    }
}, {
    sequelize,
    tableName: 'user_review',
    underscored: true,
    timestamps: true
});

module.exports = { UserReview };
