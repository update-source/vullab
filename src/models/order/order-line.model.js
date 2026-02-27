const { DataTypes, Model, sequelize } = require("../../config/database.config");

class OrderLine extends Model {}

OrderLine.init(
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
    },
    orderId: {
      type: DataTypes.UUID,
      allowNull: false,
      references: {
        model: "shop_order",
        key: "id",
      },
    },
    productItemId: {
      type: DataTypes.UUID,
      allowNull: false,
      references: {
        model: "product_item",
        key: "id",
      },
    },
    quantity: {
      type: DataTypes.INTEGER,
      allowNull: false,
      validate: { min: 1 },
    },
    unitPrice: {
      type: DataTypes.DECIMAL(10, 2),
      allowNull: false,
    },
    totalPrice: {
      type: DataTypes.DECIMAL(10, 2),
      allowNull: false,
    },

    // Snapshot fields
    productName: {
      type: DataTypes.STRING(255),
      allowNull: false,
    },
    productSku: {
      type: DataTypes.STRING(50),
      allowNull: false,
    },
  },
  {
    sequelize,
    tableName: "order_line",
    underscored: true,
    timestamps: true,
    updatedAt: false,
  },
);

module.exports = { OrderLine };
