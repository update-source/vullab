const { DataTypes, Model, sequelize } = require("../../config/database.config");

class Country extends Model {}

Country.init(
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
    },
    countryName: {
      type: DataTypes.STRING(100),
      allowNull: false,
    },
    countryCode: {
      type: DataTypes.STRING(10),
      allowNull: false,
    },
  },
  {
    sequelize,
    tableName: "country",
    underscored: true,
  },
);

module.exports = { Country };
