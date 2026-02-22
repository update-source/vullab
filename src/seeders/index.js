const { sequelize } = require("../models");
const {
  User,
  UserProfile,
  Category,
  Product,
  ProductItem,
  OrderStatus,
  ShippingMethod,
  PaymentMethod,
  Country,
} = require("../models");
const referenceData = require("./data/reference.data");
const dummyData = require("./data/dummy.data");
const bcrypt = require("bcryptjs");

const isDev = process.env.NODE_ENV !== "production";

/**
 * Helper: Upsert (Update or Insert) để đảm bảo không trùng lặp
 */
async function seedReferenceTable(Model, data, uniqueFields, transaction) {
  console.log(`⏳ Seeding ${Model.name}...`);
  for (const item of data) {
    // Tìm bản ghi dựa trên unique field (ví dụ: code)
    const whereClause = {};
    uniqueFields.forEach((field) => (whereClause[field] = item[field]));

    const exists = await Model.findOne({ where: whereClause, transaction });

    if (exists) {
      // Update nếu cần update thông tin mới
      await exists.update(item, { transaction });
    } else {
      // Create mới
      await Model.create(item, { transaction });
    }
  }
  console.log(`✅ ${Model.name} seeded.`);
}

const seedDatabase = async () => {
  const t = await sequelize.transaction();

  try {
    console.log("🚀 Starting Database Seeder...");
    console.log(`🌍 Environment: ${process.env.NODE_ENV || "development"}`);

    // ==========================================
    // 1. CORE REFERENCE DATA (Luôn chạy)
    // ==========================================

    await seedReferenceTable(
      OrderStatus,
      referenceData.orderStatuses,
      ["code"],
      t,
    );
    await seedReferenceTable(
      PaymentMethod,
      referenceData.paymentMethods,
      ["code"],
      t,
    );
    await seedReferenceTable(
      ShippingMethod,
      referenceData.shippingMethods,
      ["code"],
      t,
    );
    await seedReferenceTable(
      Country,
      referenceData.countries,
      ["countryCode"],
      t,
    );

    // System Admin Account (Luôn đảm bảo hệ thống có ít nhất 1 admin)
    // Production: Pass qua ENV, Dev: Pass mặc định
    const adminEmail = process.env.ADMIN_EMAIL || "admin@vullab.com";
    const adminPass = process.env.ADMIN_PASSWORD || "PleaseChangeMe123!";

    const existingAdmin = await User.findOne({
      where: { email: adminEmail },
      transaction: t,
    });

    if (!existingAdmin) {
      console.log("👤 Creating System Admin...");
      const hashedPassword = await bcrypt.hash(adminPass, 12);
      const admin = await User.create(
        {
          username: "admin", // Cần unique
          email: adminEmail,
          password: hashedPassword,
          role: "admin",
          isActive: true,
          isEmailVerified: true,
        },
        { transaction: t },
      );

      await UserProfile.create(
        {
          userID: admin.id,
          firstName: "System",
          lastName: "Administrator",
        },
        { transaction: t },
      );
    } else {
      console.log("ℹ️ System Admin already exists. Skipping.");
    }

    // ==========================================
    // 2. DUMMY DATA FOR DEVELOPMENT
    // ==========================================

    if (isDev) {
      console.log("🧪 Detected Development Environment. Seeding Dummy Data...");

      // --- Categories ---
      // Logic đệ quy đơn giản cho 1 cấp parent-child
      for (const catData of dummyData.categories) {
        const [parentCat] = await Category.findOrCreate({
          where: { slug: catData.slug },
          defaults: { categoryName: catData.categoryName },
          transaction: t,
        });

        if (catData.children) {
          for (const childData of catData.children) {
            await Category.findOrCreate({
              where: { slug: childData.slug },
              defaults: {
                categoryName: childData.categoryName,
                parentCategoryId: parentCat.id,
              },
              transaction: t,
            });
          }
        }
      }
      console.log("✅ Dummy Categories seeded.");

      // --- Products ---
      // Cần lấy category ID thật để gán
      const phoneCat = await Category.findOne({
        where: { slug: "dien-thoai" },
        transaction: t,
      });
      const laptopCat = await Category.findOne({
        where: { slug: "laptop" },
        transaction: t,
      });

      if (phoneCat && laptopCat) {
        for (const prodData of dummyData.products) {
          // Xác định category dựa trên logic đơn giản (demo)
          const catId = prodData.name.includes("iPhone")
            ? phoneCat.id
            : laptopCat.id;

          const [prod] = await Product.findOrCreate({
            where: { sku: prodData.sku },
            defaults: {
              name: prodData.name,
              categoryId: catId,
              description: prodData.description,
              isPublished: true,
            },
            transaction: t,
          });

          // Variations
          for (const variant of prodData.variants) {
            await ProductItem.findOrCreate({
              where: { sku: variant.sku },
              defaults: {
                productId: prod.id,
                price: variant.price,
                quantityInStock: variant.quantityInStock,
              },
              transaction: t,
            });
          }
        }
        console.log("✅ Dummy Products seeded.");
      }
    } else {
      console.log("🏭 Production Environment detected. Skipping dummy data.");
    }

    await t.commit();
    console.log("🎉 Seeding Completed Successfully without Errors.");
    process.exit(0);
  } catch (error) {
    await t.rollback();
    console.error("❌ Seeding Failed. Rolled back all changes.");
    console.error(error);
    process.exit(1);
  }
};

seedDatabase();
