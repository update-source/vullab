const { sequelize, DataTypes, Model } = require("../../config/database.config");

class LoginAttempt extends Model {}

LoginAttempt.init(
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
    },
    ipAddress: {
      type: DataTypes.STRING(45),
      allowNull: false,
      comment: "IP address attempting to login",
    },
    attemptCount: {
      type: DataTypes.INTEGER,
      defaultValue: 0,
      allowNull: false,
      comment: "Number of failed login attempts",
    },
    blockedUntil: {
      type: DataTypes.DATE,
      allowNull: true,
      comment: "Timestamp when the block expires",
    },
    lastAttempt: {
      type: DataTypes.DATE,
      allowNull: true,
      comment: "Timestamp of the last login attempt",
    },
    metadata: {
      type: DataTypes.JSONB,
      defaultValue: {},
      comment: "Additional data: user_agent, attempted_email, etc.",
    },
  },
  {
    sequelize,
    tableName: "login_attempt",
    underscored: true,
    timestamps: true,
    indexes: [{ unique: true, fields: ["ip_address"] }],
  },
);

module.exports = { LoginAttempt };
