const { sequelize, DataTypes, Model } = require("../../config/database.config");

class ShippingMethod extends Model {}

ShippingMethod.init(
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
    },
    code: {
      type: DataTypes.STRING(50),
      allowNull: false,
      unique: true,
    },
    name: {
      type: DataTypes.STRING(100),
      allowNull: false,
    },
    description: {
      type: DataTypes.TEXT,
    },
    price: {
      type: DataTypes.DECIMAL(10, 2),
      allowNull: false,
    },
    estimatedDaysMin: {
      type: DataTypes.INTEGER,
      allowNull: false,
    },
    estimatedDaysMax: {
      type: DataTypes.INTEGER,
      allowNull: false,
    },
    isActive: {
      type: DataTypes.BOOLEAN,
      defaultValue: true,
    },
  },
  {
    sequelize,
    tableName: "shipping_method",
    underscored: true,
    timestamps: true,
    updatedAt: false,
  },
);

module.exports = { ShippingMethod };
