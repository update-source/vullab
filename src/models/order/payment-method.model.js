const { DataTypes, Model, sequelize } = require("../../config/database.config");

class PaymentMethod extends Model {}

PaymentMethod.init(
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
    methodName: {
      type: DataTypes.STRING(100),
      allowNull: false,
    },
    description: {
      type: DataTypes.TEXT,
    },
    isActive: {
      type: DataTypes.BOOLEAN,
      defaultValue: true,
    },
    processingFeePercentage: {
      type: DataTypes.DECIMAL(5, 2),
      defaultValue: 0.0,
    },
  },
  {
    sequelize,
    tableName: "payment_method",
    underscored: true,
    timestamps: false,
  },
);

module.exports = { PaymentMethod };
