# 📋 ERD Review & Update Checklist

> **Mục đích:** Hướng dẫn review và bổ sung ERD để đảm bảo đầy đủ các trường cần thiết cho VulLab

---

## 🎯 Quy Tắc Chung Khi Sửa ERD

1. ✅ **Tên bảng:** `snake_case`, số ít (singular): `user`, `shop_order`, `product_item`
2. ✅ **Tên cột:** `snake_case`: `user_id`, `created_at`, `is_active`
3. ✅ **Primary Key:** Luôn có `id` (INTEGER AUTO_INCREMENT) hoặc composite key
4. ✅ **Foreign Key:** Đặt tên theo format `<table_name>_id`: `user_id`, `product_id`
5. ✅ **Timestamps:** Thêm `created_at` và `updated_at` cho mọi bảng chính
6. ✅ **Indexes:** Đánh dấu các cột cần index (email, username, foreign keys)

---

## 📊 BẢNG 1: `user`

### Current Fields (Từ ERD hiện tại):
- [ ] `id` (PK)
- [ ] `email_address`
- [ ] `phone_number`

### ✅ CẦN BỔ SUNG:

#### **🔑 Authentication Fields**
- [ ] `username` VARCHAR(50) UNIQUE NOT NULL
- [ ] `password` VARCHAR(255) NOT NULL *(hashed password)*
- [ ] `role` ENUM('user', 'admin') DEFAULT 'user' NOT NULL

#### **🔐 Security Fields (Cho labs)**
- [ ] `is_active` BOOLEAN DEFAULT true
- [ ] `is_email_verified` BOOLEAN DEFAULT false
- [ ] `email_verification_token` VARCHAR(255) NULL
- [ ] `password_reset_token` VARCHAR(255) NULL
- [ ] `password_reset_expires` TIMESTAMP NULL

#### **📅 Audit Fields**
- [ ] `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
- [ ] `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
- [ ] `last_login_at` TIMESTAMP NULL

#### **🎯 Optional (Cho advanced labs)**
- [ ] `login_attempts` INTEGER DEFAULT 0 *(bruteforce protection)*
- [ ] `locked_until` TIMESTAMP NULL *(account lockout)*

### ⚙️ Indexes cần tạo:
```sql
CREATE UNIQUE INDEX idx_user_email ON user(email_address);
CREATE UNIQUE INDEX idx_user_username ON user(username);
CREATE INDEX idx_user_role ON user(role);
CREATE INDEX idx_user_reset_token ON user(password_reset_token);
```

---

## 📊 BẢNG 2: `user_profile`

### Current Fields:
- [ ] `user_id` (FK)
- [ ] `first_name`
- [ ] `last_name`

### ✅ CẦN BỔ SUNG:

- [ ] `id` INTEGER PRIMARY KEY AUTO_INCREMENT *(nếu chưa có)*
- [ ] `date_of_birth` DATE NULL
- [ ] `phone_number` VARCHAR(20) NULL *(move từ user sang đây)*
- [ ] `avatar_url` VARCHAR(255) NULL
- [ ] `bio` TEXT NULL
- [ ] `created_at` TIMESTAMP
- [ ] `updated_at` TIMESTAMP

---

## 📊 BẢNG 3: `address`

### Current Fields (Review):
- [ ] `line1`
- [ ] `line2`
- [ ] `city`
- [ ] `zip_code`

### ✅ CẦN BỔ SUNG/RENAME:

- [ ] `id` INTEGER PK
- [ ] `street_address` VARCHAR(255) *(rename từ line1)*
- [ ] `street_address_2` VARCHAR(255) NULL *(rename từ line2)*
- [ ] `city` VARCHAR(100)
- [ ] `state_province` VARCHAR(100) NULL
- [ ] `postal_code` VARCHAR(20) *(rename từ zip_code)*
- [ ] `country_id` INTEGER FK → country(id)
- [ ] `is_default` BOOLEAN DEFAULT false
- [ ] `address_type` ENUM('shipping', 'billing', 'both') DEFAULT 'both'
- [ ] `created_at` TIMESTAMP
- [ ] `updated_at` TIMESTAMP

---

## 📊 BẢNG 4: `product`

### Current Fields:
- [ ] `id`
- [ ] `category_id`
- [ ] `name`
- [ ] `description`
- [ ] `product_image`

### ✅ CẦN BỔ SUNG:

#### **💰 Pricing (Cho logic flaw labs)**
- [ ] `base_price` DECIMAL(10,2) NULL *(giá gốc, có thể không có nếu dùng product_item)*

#### **📦 Inventory**
- [ ] `sku` VARCHAR(50) UNIQUE NULL *(Stock Keeping Unit)*
- [ ] `is_published` BOOLEAN DEFAULT true *(Cho IDOR labs: xem product ẩn)*

#### **📊 Metadata**
- [ ] `view_count` INTEGER DEFAULT 0
- [ ] `rating_average` DECIMAL(3,2) DEFAULT 0.00
- [ ] `review_count` INTEGER DEFAULT 0

#### **📅 Timestamps**
- [ ] `created_at` TIMESTAMP
- [ ] `updated_at` TIMESTAMP
- [ ] `published_at` TIMESTAMP NULL

### ⚙️ Indexes:
```sql
CREATE INDEX idx_product_category ON product(category_id);
CREATE INDEX idx_product_published ON product(is_published);
CREATE UNIQUE INDEX idx_product_sku ON product(sku);
```

---

## 📊 BẢNG 5: `product_item`

### Current Fields:
- [ ] `id`
- [ ] `product_id`
- [ ] `SKU`
- [ ] `qty_in_stock`
- [ ] `product_image`
- [ ] `price`

### ✅ CẦN SỬA/BỔ SUNG:

#### **Rename/Fix:**
- [ ] `sku` VARCHAR(50) UNIQUE *(lowercase)*
- [ ] `quantity_in_stock` INTEGER *(rename từ qty_in_stock)*
- [ ] `price` DECIMAL(10,2) NOT NULL

#### **Thêm mới:**
- [ ] `original_price` DECIMAL(10,2) NULL *(giá gốc trước khi giảm)*
- [ ] `is_active` BOOLEAN DEFAULT true
- [ ] `created_at` TIMESTAMP
- [ ] `updated_at` TIMESTAMP

---

## 📊 BẢNG 6: `category`

### Current Fields:
- [ ] `id`
- [ ] `category_name`

### ✅ CẦN BỔ SUNG:

- [ ] `parent_category_id` INTEGER NULL FK → category(id) *(nested categories)*
- [ ] `slug` VARCHAR(100) UNIQUE *(URL-friendly: "electronics")*
- [ ] `description` TEXT NULL
- [ ] `image_url` VARCHAR(255) NULL
- [ ] `is_active` BOOLEAN DEFAULT true
- [ ] `display_order` INTEGER DEFAULT 0
- [ ] `created_at` TIMESTAMP
- [ ] `updated_at` TIMESTAMP

---

## 📊 BẢNG 7: `shop_order`

### Current Fields:
- [ ] `id`
- [ ] `user_id`
- [ ] `order_date`
- [ ] `payment_method_id`
- [ ] `shipping_address`
- [ ] `shipping_method`
- [ ] `order_total`
- [ ] `order_status`

### ✅ CẦN SỬA/BỔ SUNG:

#### **Fix Foreign Keys:**
- [ ] `shipping_address_id` INTEGER FK → address(id) *(thay vì text)*
- [ ] `shipping_method_id` INTEGER FK → shipping_method(id)
- [ ] `order_status_id` INTEGER FK → order_status(id) *(thay vì text)*

#### **Pricing (QUAN TRỌNG cho labs):**
- [ ] `subtotal` DECIMAL(10,2) NOT NULL *(tổng giá sản phẩm)*
- [ ] `shipping_cost` DECIMAL(10,2) DEFAULT 0.00
- [ ] `tax_amount` DECIMAL(10,2) DEFAULT 0.00
- [ ] `discount_amount` DECIMAL(10,2) DEFAULT 0.00 *(từ promotion)*
- [ ] `final_total` DECIMAL(10,2) NOT NULL *(rename từ order_total)*

#### **Tracking:**
- [ ] `order_number` VARCHAR(50) UNIQUE NOT NULL *(ORD-2024-00001)*
- [ ] `tracking_number` VARCHAR(100) NULL
- [ ] `notes` TEXT NULL

#### **Timestamps:**
- [ ] `created_at` TIMESTAMP *(rename từ order_date)*
- [ ] `updated_at` TIMESTAMP
- [ ] `paid_at` TIMESTAMP NULL
- [ ] `shipped_at` TIMESTAMP NULL
- [ ] `delivered_at` TIMESTAMP NULL

---

## 📊 BẢNG 8: `order_line` (Order Items)

### Current Fields:
- [ ] `order_id`
- [ ] `product_item_id`
- [ ] `qty`
- [ ] `price`

### ✅ CẦN BỔ SUNG:

- [ ] `id` INTEGER PK AUTO_INCREMENT
- [ ] `quantity` INTEGER NOT NULL *(rename từ qty)*
- [ ] `unit_price` DECIMAL(10,2) NOT NULL *(giá 1 sản phẩm)*
- [ ] `total_price` DECIMAL(10,2) NOT NULL *(quantity * unit_price)*
- [ ] `product_name` VARCHAR(255) *(snapshot tên sản phẩm tại thời điểm mua)*
- [ ] `product_sku` VARCHAR(50) *(snapshot SKU)*
- [ ] `created_at` TIMESTAMP

**💡 Lý do snapshot:** Nếu sản phẩm bị xóa/đổi tên sau này, order vẫn hiển thị đúng.

---

## 📊 BẢNG 9: `shopping_cart`

### Current Fields:
- [ ] `user_id`

### ✅ CẦN BỔ SUNG:

- [ ] `id` INTEGER PK AUTO_INCREMENT
- [ ] `created_at` TIMESTAMP
- [ ] `updated_at` TIMESTAMP
- [ ] `expires_at` TIMESTAMP NULL *(cart tự động xóa sau X ngày)*

---

## 📊 BẢNG 10: `shopping_cart_item`

### Current Fields:
- [ ] `cart_id`
- [ ] `product_item_id`
- [ ] `qty`

### ✅ CẦN BỔ SUNG:

- [ ] `id` INTEGER PK
- [ ] `quantity` INTEGER *(rename)*
- [ ] `created_at` TIMESTAMP
- [ ] `updated_at` TIMESTAMP

---

## 📊 BẢNG 11: `user_review`

### Current Fields (nếu có):
- [ ] `user_id`
- [ ] `ordered_product_id`
- [ ] `rating_value`
- [ ] `comment`

### ✅ CẦN SỬA/BỔ SUNG:

- [ ] `id` INTEGER PK
- [ ] `product_id` INTEGER FK *(thay vì ordered_product_id)*
- [ ] `user_id` INTEGER FK
- [ ] `order_id` INTEGER FK NULL *(chỉ review được nếu đã mua)*
- [ ] `rating` INTEGER CHECK (rating BETWEEN 1 AND 5)
- [ ] `title` VARCHAR(200) NULL
- [ ] `comment` TEXT *(QUAN TRỌNG: Cho XSS labs)*
- [ ] `is_verified_purchase` BOOLEAN DEFAULT false
- [ ] `is_approved` BOOLEAN DEFAULT true *(moderation)*
- [ ] `helpful_count` INTEGER DEFAULT 0
- [ ] `created_at` TIMESTAMP
- [ ] `updated_at` TIMESTAMP

---

## 📊 BẢNG 12: `promotion`

### Current Fields:
- [ ] `id`
- [ ] `name`
- [ ] `discount_rate`
- [ ] `start_date`
- [ ] `end_date`

### ✅ CẦN BỔ SUNG:

- [ ] `code` VARCHAR(50) UNIQUE *(PROMO2024)*
- [ ] `description` TEXT NULL
- [ ] `discount_type` ENUM('percentage', 'fixed_amount') DEFAULT 'percentage'
- [ ] `discount_value` DECIMAL(10,2) *(rename từ discount_rate)*
- [ ] `minimum_order_amount` DECIMAL(10,2) NULL
- [ ] `max_discount_amount` DECIMAL(10,2) NULL *(nếu %, tối đa giảm bao nhiêu)*
- [ ] `usage_limit` INTEGER NULL *(tối đa X lượt dùng)*
- [ ] `usage_count` INTEGER DEFAULT 0
- [ ] `is_active` BOOLEAN DEFAULT true
- [ ] `created_at` TIMESTAMP
- [ ] `updated_at` TIMESTAMP

---

## 📊 BẢNG 13: `payment_method`

### Current Fields (Reference table):
- [ ] `id`
- [ ] `method_name`

### ✅ CẦN BỔ SUNG:

- [ ] `code` VARCHAR(50) UNIQUE *(credit_card, paypal, cod)*
- [ ] `description` TEXT
- [ ] `is_active` BOOLEAN DEFAULT true
- [ ] `processing_fee_percentage` DECIMAL(5,2) DEFAULT 0.00
- [ ] `icon_url` VARCHAR(255) NULL

**💡 Ví dụ data:**
```sql
INSERT INTO payment_method VALUES 
(1, 'credit_card', 'Credit/Debit Card', true, 2.50),
(2, 'paypal', 'PayPal', true, 3.00),
(3, 'cod', 'Cash on Delivery', true, 0.00);
```

---

## 📊 BẢNG 14: `shipping_method`

### Current Fields:
- [ ] `id`
- [ ] `name`
- [ ] `price`

### ✅ CẦN BỔ SUNG:

- [ ] `code` VARCHAR(50) UNIQUE *(standard, express, overnight)*
- [ ] `description` TEXT
- [ ] `estimated_days_min` INTEGER *(3 ngày)*
- [ ] `estimated_days_max` INTEGER *(7 ngày)*
- [ ] `is_active` BOOLEAN DEFAULT true
- [ ] `created_at` TIMESTAMP

---

## 📊 BẢNG 15: `order_status`

### Current Fields (Reference table):
- [ ] `id`
- [ ] `status`

### ✅ CẦN BỔ SUNG:

- [ ] `code` VARCHAR(50) UNIQUE *(pending, processing, shipped, delivered, cancelled)*
- [ ] `display_name` VARCHAR(100) *(rename từ status)*
- [ ] `description` TEXT
- [ ] `color` VARCHAR(7) NULL *('#28a745' cho delivered)*
- [ ] `display_order` INTEGER DEFAULT 0

---

## 📊 BẢNG MỚI CẦN THÊM

### ✅ BẢNG 16: `variation`
*(Đã có trong ERD - CHỈ CẦN REVIEW)*

- [ ] `id` PK
- [ ] `category_id` FK
- [ ] `name` VARCHAR(100) *(Color, Size, Material)*
- [ ] `created_at` TIMESTAMP

---

### ✅ BẢNG 17: `variation_option`
*(Đã có - CHỈ CẦN REVIEW)*

- [ ] `id` PK
- [ ] `variation_id` FK
- [ ] `value` VARCHAR(100) *(Red, Blue, XL, Cotton)*
- [ ] `created_at` TIMESTAMP

---

### ✅ BẢNG 18: `product_configuration`
*(Đã có - CHỈ CẦN REVIEW)*

- [ ] `product_item_id` FK
- [ ] `variation_option_id` FK

**💡 Composite Primary Key:** (product_item_id, variation_option_id)

---

## 🎯 Workflow Thực Hiện

### **Bước 1: Backup ERD hiện tại**
```
1. Copy file erd_ecommerce_database.png
2. Rename thành erd_ecommerce_database_v1_backup.png
```

### **Bước 2: Mở tool ERD của bạn**
*(dbdiagram.io, draw.io, MySQL Workbench, etc.)*

### **Bước 3: Làm theo checklist**
1. ✅ Đi qua TỪNG BẢNG ở trên
2. ✅ Tick vào các field đã có
3. ✅ Thêm các field còn thiếu
4. ✅ Đổi tên field không chuẩn (qty → quantity)
5. ✅ Thêm indexes cần thiết

### **Bước 4: Validate ERD**
- [ ] Mọi bảng đều có Primary Key
- [ ] Foreign Keys đều có constraint name rõ ràng
- [ ] Tất cả bảng chính đều có `created_at`, `updated_at`
- [ ] ENUM values đều được define rõ ràng
- [ ] Decimal fields có precision đúng: DECIMAL(10,2)

### **Bước 5: Export**
```
1. Export ERD mới thành erd_ecommerce_database_v2.png
2. Export SQL schema script → schema.sql (nếu tool hỗ trợ)
```

### **Bước 6: Document Changes**
Tạo file `ERD_CHANGES.md` ghi lại:
```markdown
# ERD Changes v1 → v2

## Added Fields
- user.username
- user.role
- product.is_published
...

## Renamed Fields
- shop_order.order_total → final_total
- order_line.qty → quantity
...

## New Tables
(Nếu có)
```

---

## 📝 Notes

### **Các trường QUAN TRỌNG cho VulLab:**

1. **`user.role`** → Auth/Authorization labs
2. **`product.is_published`** → IDOR labs (xem sản phẩm ẩn)
3. **`user_review.comment`** → XSS labs (Stored XSS)
4. **`shop_order.final_total`, `discount_amount`** → Logic flaw labs (price manipulation)
5. **`user.password_reset_token`** → Broken Authentication labs
6. **`promotion.code`** → Logic flaw labs (coupon bypass)

### **Các trường có thể bỏ qua ở v1:**
- `user.login_attempts`, `locked_until` (bruteforce labs - advanced)
- `product.view_count`, `rating_average` (analytics - không cần thiết)
- `variation`, `variation_option` (phức tạp - có thể làm sau)

---

## ✅ Khi Nào Coi Như Xong?

- [ ] Đã review hết 18 bảng
- [ ] Đã thêm đủ các trường bắt buộc (role, timestamps, foreign keys đúng)
- [ ] ERD chạy được migration không lỗi
- [ ] Đã save file mới: `erd_ecommerce_database_v2.png`

---

**📌 Sau khi sửa xong ERD, hãy:**
1. Show tôi ERD mới hoặc paste SQL schema
2. Tôi sẽ generate code Sequelize models dựa trên ERD mới
3. Bắt đầu code API!

Good luck! 🚀
