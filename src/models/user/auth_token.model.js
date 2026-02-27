const { DataTypes, Model, sequelize } = require("../../config/database.config");

/**
 * AuthToken Model - "Remember Me" persistent login tokens
 *
 * Implements the split-token pattern for secure persistent sessions:
 *   - `selector`        : stored in cookie, used to LOOK UP the row (public)
 *   - `hashedValidator` : SHA-256 hash of the secret part stored in cookie
 *
 * The cookie value sent to the client is: `<selector>:<validator>` (plaintext validator)
 * The database only stores SHA-256(validator), so a DB leak cannot be used to log in.
 *
 * References:
 *   https://paragonie.com/blog/2015/04/secure-authentication-php-with-long-term-persistence
 */
class AuthToken extends Model {}

AuthToken.init(
  {
    id: {
      type: DataTypes.INTEGER.UNSIGNED,
      autoIncrement: true,
      primaryKey: true,
    },

    selector: {
      type: DataTypes.CHAR(16),
      allowNull: false,
      comment:
        "Public part of the token stored in cookie. Used to find the DB row.",
    },

    hashedValidator: {
      type: DataTypes.CHAR(64),
      allowNull: false,
      comment:
        "SHA-256 hash of the validator. Plaintext validator lives only in the cookie.",
    },

    userId: {
      type: DataTypes.UUID,
      allowNull: false,
      references: {
        model: "user",
        key: "id",
      },
      comment: "Owner of this persistent session token",
    },

    expires: {
      type: DataTypes.DATE,
      allowNull: false,
      comment: "Token expiry datetime",
    },

    ipAddress: {
      type: DataTypes.STRING(45),
      allowNull: true,
      comment: "IP address that created this token",
    },

    userAgent: {
      type: DataTypes.TEXT,
      allowNull: true,
      comment: "User-Agent string that created this token",
    },
  },
  {
    sequelize,
    tableName: "auth_token",
    underscored: true,
    timestamps: true,
    indexes: [
      {
        unique: true,
        fields: ["selector"],
      },
      {
        fields: ["expires"],
      },
      {
        fields: ["user_id"],
      },
    ],
  },
);

module.exports = { AuthToken };
