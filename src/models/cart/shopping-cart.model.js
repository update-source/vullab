const { sequelize, DataTypes, Model } = require("../../config/database.config");

class ShoppingCart extends Model {}

ShoppingCart.init(
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
    },
    userId: {
      type: DataTypes.UUID,
      allowNull: false,
      unique: true,
      references: {
        model: "user",
        key: "id",
      },
    },
    expiresAt: {
      type: DataTypes.DATE,
    },
  },
  {
    sequelize,
    tableName: "shopping_cart",
    underscored: true,
    timestamps: true,
  },
);

module.exports = { ShoppingCart };
