const { DataTypes, Model, sequelize } = require("../../config/database.config");

class Promotion extends Model {}

Promotion.init(
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
    discountType: {
      type: DataTypes.ENUM("percentage", "fixed_amount"),
      defaultValue: "percentage",
    },
    discountValue: {
      type: DataTypes.DECIMAL(10, 2),
      allowNull: false,
    },
    minimumOrderAmount: {
      type: DataTypes.DECIMAL(10, 2),
    },
    maxDiscountAmount: {
      type: DataTypes.DECIMAL(10, 2),
    },
    usageLimit: {
      type: DataTypes.INTEGER,
    },
    usageCount: {
      type: DataTypes.INTEGER,
      defaultValue: 0,
    },
    isActive: {
      type: DataTypes.BOOLEAN,
      defaultValue: true,
    },
    startDate: {
      type: DataTypes.DATE,
      allowNull: false,
    },
    endDate: {
      type: DataTypes.DATE,
      allowNull: false,
    },
  },
  {
    sequelize,
    tableName: "promotion",
    underscored: true,
    timestamps: true,
  },
);

module.exports = { Promotion };
