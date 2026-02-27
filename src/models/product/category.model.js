const { DataTypes, Model, sequelize } = require("../../config/database.config");

class Category extends Model {}

Category.init(
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
    },
    parentCategoryId: {
      type: DataTypes.UUID,
      allowNull: true,
      references: {
        model: "category",
        key: "id",
      },
    },
    categoryName: {
      type: DataTypes.STRING(100),
      allowNull: false,
    },
    slug: {
      type: DataTypes.STRING(100),
      allowNull: false,
      unique: true,
    },
    description: {
      type: DataTypes.TEXT,
    },
    isActive: {
      type: DataTypes.BOOLEAN,
      defaultValue: true,
    },
    displayOrder: {
      type: DataTypes.INTEGER,
      defaultValue: 0,
    },
  },
  {
    sequelize,
    tableName: "category",
    underscored: true,
    timestamps: true,
  },
);

module.exports = { Category };
