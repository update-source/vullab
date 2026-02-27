const { DataTypes, Model, sequelize } = require("../../config/database.config");

class OrderStatus extends Model {}

OrderStatus.init(
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
    displayName: {
      type: DataTypes.STRING(100),
      allowNull: false,
    },
    description: {
      type: DataTypes.TEXT,
    },
    color: {
      type: DataTypes.STRING(7),
    },
    displayOrder: {
      type: DataTypes.INTEGER,
      defaultValue: 0,
    },
  },
  {
    sequelize,
    tableName: "order_status",
    underscored: true,
    timestamps: false,
  },
);

module.exports = { OrderStatus };
