const { sequelize, DataTypes, Model } = require("../../config/database.config");

class UserSetting extends Model {}

UserSetting.init(
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
    enable2FA: {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
    },
    loginNotifications: {
      type: DataTypes.BOOLEAN,
      defaultValue: true,
    },
    profileVisibility: {
      type: DataTypes.ENUM("public", "private"),
      defaultValue: "public",
    },
    preferences: {
      type: DataTypes.JSONB,
      defaultValue: {},
    },
  },
  {
    sequelize,
    tableName: "user_setting",
    underscored: true,
    timestamps: true,
  },
);

module.exports = { UserSetting };
