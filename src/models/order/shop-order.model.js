const { DataTypes, Model, sequelize } = require("../../config/database.config");

class ShopOrder extends Model {}

ShopOrder.init(
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
    },
    userId: {
      type: DataTypes.UUID,
      allowNull: false,
      references: {
        model: "user",
        key: "id",
      },
    },
    orderNumber: {
      type: DataTypes.STRING(50),
      allowNull: false,
      unique: true,
    },

    // Pricing Breakdown
    subtotal: {
      type: DataTypes.DECIMAL(10, 2),
      allowNull: false,
    },
    shippingCost: {
      type: DataTypes.DECIMAL(10, 2),
      defaultValue: 0.0,
    },
    taxAmount: {
      type: DataTypes.DECIMAL(10, 2),
      defaultValue: 0.0,
    },
    discountAmount: {
      type: DataTypes.DECIMAL(10, 2),
      defaultValue: 0.0,
    },
    finalTotal: {
      type: DataTypes.DECIMAL(10, 2),
      allowNull: false,
    },

    // Foreign Keys
    shippingAddressId: {
      type: DataTypes.UUID,
      allowNull: false,
      references: {
        model: "address",
        key: "id",
      },
    },
    shippingMethodId: {
      type: DataTypes.UUID,
      allowNull: false,
      references: {
        model: "shipping_method",
        key: "id",
      },
    },
    paymentMethodId: {
      type: DataTypes.UUID,
      allowNull: false,
      references: {
        model: "payment_method",
        key: "id",
      },
    },
    orderStatusId: {
      type: DataTypes.UUID,
      allowNull: false,
      references: {
        model: "order_status",
        key: "id",
      },
    },

    // Info
    trackingNumber: {
      type: DataTypes.STRING(100),
    },
    notes: {
      type: DataTypes.TEXT,
    },

    // Timestamps
    paidAt: DataTypes.DATE,
    shippedAt: DataTypes.DATE,
    deliveredAt: DataTypes.DATE,
  },
  {
    sequelize,
    tableName: "shop_order",
    underscored: true,
    timestamps: true,
  },
);

module.exports = { ShopOrder };
