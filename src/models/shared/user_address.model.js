const { sequelize, DataTypes, Model } = require("../../config/database.config");

class UserAddress extends Model {}

UserAddress.init(
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
      onUpdate: "CASCADE",
      onDelete: "CASCADE",
    },
    addressId: {
      type: DataTypes.UUID,
      allowNull: false,
      references: {
        model: "address",
        key: "id",
      },
    },
    isDefault: {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
    },
    addressType: {
      type: DataTypes.ENUM("shipping", "billing", "both"),
      allowNull: false,
      defaultValue: "both",
    },
  },
  {
    sequelize,
    tableName: "user_address",
    underscored: true,
    timestamps: true,
  },
);

module.exports = { UserAddress };
