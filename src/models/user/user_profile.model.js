const { sequelize, DataTypes, Model } = require("../../config/database.config");

class UserProfile extends Model {}

UserProfile.init(
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
    },
    userID: {
      type: DataTypes.UUID,
      allowNull: false,
      references: {
        model: "user",
        key: "id",
      },
    },
    firstName: {
      type: DataTypes.STRING(100),
    },
    lastName: {
      type: DataTypes.STRING(100),
    },
    phoneNumber: {
      type: DataTypes.STRING(20),
    },
    dateOfBirth: {
      type: DataTypes.DATE,
    },
    avatarUrl: {
      type: DataTypes.STRING(255),
    },
    bio: {
      type: DataTypes.TEXT,
    },
  },
  {
    sequelize,
    tableName: "user_profile",
    timestamps: true,
    underscored: true,
  },
);

module.exports = { UserProfile };
