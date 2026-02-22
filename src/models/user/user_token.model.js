const { sequelize, DataTypes, Model } = require("../../config/database.config");

class UserToken extends Model {}

UserToken.init(
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
    tokenType: {
      type: DataTypes.ENUM(
        "password_reset",
        "email_verification",
        "api_token",
        "session_token",
      ),
      allowNull: false,
    },
    tokenValue: {
      type: DataTypes.STRING(255),
      allowNull: false,
    },
    expiresAt: {
      type: DataTypes.DATE,
    },
    isUsed: {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
    },
    usedAt: {
      type: DataTypes.DATE,
    },
    ipAddress: {
      type: DataTypes.STRING(45),
    },
    userAgent: {
      type: DataTypes.TEXT,
    },
  },
  {
    sequelize,
    tableName: "user_token",
    underscored: true,
    timestamps: true,
  },
);

module.exports = { UserToken };
