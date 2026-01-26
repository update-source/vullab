# 🎯 ERD Modular Design - Scalable Architecture

> **Philosophy:** Simple now, Easy to scale later  
> **Approach:** Core fields embedded + Advanced features in separate tables

---

## 📋 **Summary of Changes from Original ERD**

### **What's Different:**
1. ✅ **`user` table:** Giữ lại chỉ 10 core fields (loại bỏ token fields)
2. ✅ **NEW `user_token` table:** Centralized token management (extensible)
3. ✅ **NEW `user_security_log` table:** (Optional) Audit & bruteforce protection
4. ✅ **NEW `user_setting` table:** (Optional) User preferences

### **Why This Design:**
- 🚀 **v1 Simple:** Chỉ cần `user` + `user_token` tables
- 📈 **v2+ Scalable:** Dễ thêm tables mới mà không sửa `user`
- 🔒 **Separation:** Security logic tách biệt khỏi identity data

---

## 🗂️ **FULL ERD SCHEMA**

### **CORE TABLES (v1 - MUST HAVE)**

---

#### **TABLE 1: `user`**

**Purpose:** Core user identity + essential security status

```sql
CREATE TABLE user (
  -- Identity
  id                INTEGER PRIMARY KEY AUTO_INCREMENT,
  username          VARCHAR(50) UNIQUE NOT NULL,
  email             VARCHAR(100) UNIQUE NOT NULL,
  password          VARCHAR(255) NOT NULL,
  role              ENUM('user', 'admin') DEFAULT 'user' NOT NULL,
  
  -- Essential Security Status
  is_active         BOOLEAN DEFAULT true,
  is_email_verified BOOLEAN DEFAULT false,
  
  -- Audit Timestamps
  last_login_at     TIMESTAMP NULL,
  created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Indexes
CREATE UNIQUE INDEX idx_user_email ON user(email);
CREATE UNIQUE INDEX idx_user_username ON user(username);
CREATE INDEX idx_user_role ON user(role);
CREATE INDEX idx_user_active ON user(is_active);
```

**Fields Count:** 10 (Clean & Focused)

---

#### **TABLE 2: `user_token`**

**Purpose:** Centralized token management (password reset, email verification, API tokens, sessions)

```sql
CREATE TABLE user_token (
  id                INTEGER PRIMARY KEY AUTO_INCREMENT,
  user_id           INTEGER NOT NULL,
  token_type        ENUM(
                      'password_reset',
                      'email_verification', 
                      'api_token',
                      'session_token',
                      'refresh_token'
                    ) NOT NULL,
  token_value       VARCHAR(255) NOT NULL,
  expires_at        TIMESTAMP NULL,
  is_used           BOOLEAN DEFAULT false,
  used_at           TIMESTAMP NULL,
  ip_address        VARCHAR(45) NULL,
  user_agent        TEXT NULL,
  created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  
  FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
);

-- Indexes
CREATE INDEX idx_token_value ON user_token(token_value);
CREATE INDEX idx_user_type ON user_token(user_id, token_type);
CREATE INDEX idx_token_expires ON user_token(expires_at);
CREATE INDEX idx_token_used ON user_token(is_used);
```

**Why 1 table for all tokens?**
- ✅ Extensible: Dễ thêm token types mới
- ✅ Unified logic: 1 service handle tất cả tokens
- ✅ Audit trail: Track token usage history
- ✅ Cleanup: Dễ xóa expired tokens (1 cron job)

---

#### **TABLE 3: `user_profile`**

**Purpose:** User personal information (1-to-1 with `user`)

```sql
CREATE TABLE user_profile (
  id                INTEGER PRIMARY KEY AUTO_INCREMENT,
  user_id           INTEGER UNIQUE NOT NULL,
  first_name        VARCHAR(50) NULL,
  last_name         VARCHAR(50) NULL,
  phone_number      VARCHAR(20) NULL,
  date_of_birth     DATE NULL,
  avatar_url        VARCHAR(255) NULL,
  bio               TEXT NULL,
  created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  
  FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_profile_user ON user_profile(user_id);
```

---

### **ADVANCED TABLES (v2 - OPTIONAL)**

---

#### **TABLE 4: `user_security_log`**

**Purpose:** Audit trail + Bruteforce protection  
**Use in Labs:** Login monitoring, suspicious activity detection

```sql
CREATE TABLE user_security_log (
  id                INTEGER PRIMARY KEY AUTO_INCREMENT,
  user_id           INTEGER NULL,  -- NULL if user not found (failed login)
  event_type        ENUM(
                      'login_success',
                      'login_failed',
                      'password_changed',
                      'email_changed',
                      'account_locked',
                      'account_unlocked',
                      'token_generated',
                      'token_used'
                    ) NOT NULL,
  ip_address        VARCHAR(45) NULL,
  user_agent        TEXT NULL,
  metadata          JSON NULL,  -- Flexible: {"reason": "wrong_password", "attempts": 3}
  created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  
  FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE SET NULL
);

CREATE INDEX idx_log_user_event ON user_security_log(user_id, event_type);
CREATE INDEX idx_log_created ON user_security_log(created_at);
CREATE INDEX idx_log_ip ON user_security_log(ip_address);
```

**Lab Use Cases:**
- Detect bruteforce attacks (count `login_failed` in 5 mins)
- Track password reuse
- Audit trail lab

---

#### **TABLE 5: `user_setting`**

**Purpose:** User preferences & feature flags  
**Use in Labs:** 2FA bypass, privacy settings manipulation

```sql
CREATE TABLE user_setting (
  id                    INTEGER PRIMARY KEY AUTO_INCREMENT,
  user_id               INTEGER UNIQUE NOT NULL,
  
  -- Security Settings
  enable_2fa            BOOLEAN DEFAULT false,
  login_notifications   BOOLEAN DEFAULT true,
  session_timeout_mins  INTEGER DEFAULT 30,
  
  -- Privacy Settings
  profile_visibility    ENUM('public', 'private') DEFAULT 'public',
  show_email            BOOLEAN DEFAULT false,
  
  -- Flexible JSON for future settings
  preferences           JSON NULL,
  
  created_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  
  FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_setting_user ON user_setting(user_id);
```

---

### **OTHER CORE TABLES (Keep from original ERD)**

---

#### **TABLE: `address`**

```sql
CREATE TABLE address (
  id                INTEGER PRIMARY KEY AUTO_INCREMENT,
  street_address    VARCHAR(255) NOT NULL,
  street_address_2  VARCHAR(255) NULL,
  city              VARCHAR(100) NOT NULL,
  state_province    VARCHAR(100) NULL,
  postal_code       VARCHAR(20) NOT NULL,
  country_id        INTEGER NOT NULL,
  created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  
  FOREIGN KEY (country_id) REFERENCES country(id)
);
```

---

#### **TABLE: `user_address`** (Junction table)

```sql
CREATE TABLE user_address (
  id                INTEGER PRIMARY KEY AUTO_INCREMENT,
  user_id           INTEGER NOT NULL,
  address_id        INTEGER NOT NULL,
  is_default        BOOLEAN DEFAULT false,
  address_type      ENUM('shipping', 'billing', 'both') DEFAULT 'both',
  created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  
  FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
  FOREIGN KEY (address_id) REFERENCES address(id) ON DELETE CASCADE,
  UNIQUE KEY unique_user_address (user_id, address_id)
);
```

---

#### **TABLE: `country`**

```sql
CREATE TABLE country (
  id                INTEGER PRIMARY KEY AUTO_INCREMENT,
  country_name      VARCHAR(100) UNIQUE NOT NULL,
  country_code      VARCHAR(3) UNIQUE NOT NULL  -- ISO 3166-1 alpha-2
);

-- Seed data
INSERT INTO country (country_name, country_code) VALUES
('Vietnam', 'VN'),
('United States', 'US'),
('United Kingdom', 'GB');
```

---

#### **TABLE: `product`**

```sql
CREATE TABLE product (
  id                INTEGER PRIMARY KEY AUTO_INCREMENT,
  category_id       INTEGER NOT NULL,
  name              VARCHAR(255) NOT NULL,
  description       TEXT NULL,
  product_image     VARCHAR(255) NULL,
  sku               VARCHAR(50) UNIQUE NULL,
  
  -- 🔒 IMPORTANT for IDOR labs
  is_published      BOOLEAN DEFAULT true,
  
  created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  
  FOREIGN KEY (category_id) REFERENCES category(id)
);

CREATE INDEX idx_product_category ON product(category_id);
CREATE INDEX idx_product_published ON product(is_published);
CREATE UNIQUE INDEX idx_product_sku ON product(sku);
```

---

#### **TABLE: `category`**

```sql
CREATE TABLE category (
  id                INTEGER PRIMARY KEY AUTO_INCREMENT,
  parent_category_id INTEGER NULL,
  category_name     VARCHAR(100) NOT NULL,
  slug              VARCHAR(100) UNIQUE NOT NULL,
  description       TEXT NULL,
  is_active         BOOLEAN DEFAULT true,
  display_order     INTEGER DEFAULT 0,
  created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  
  FOREIGN KEY (parent_category_id) REFERENCES category(id) ON DELETE SET NULL
);
```

---

#### **TABLE: `product_item`**

```sql
CREATE TABLE product_item (
  id                INTEGER PRIMARY KEY AUTO_INCREMENT,
  product_id        INTEGER NOT NULL,
  sku               VARCHAR(50) UNIQUE NOT NULL,
  price             DECIMAL(10,2) NOT NULL,
  original_price    DECIMAL(10,2) NULL,
  quantity_in_stock INTEGER NOT NULL DEFAULT 0,
  product_image     VARCHAR(255) NULL,
  is_active         BOOLEAN DEFAULT true,
  created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  
  FOREIGN KEY (product_id) REFERENCES product(id) ON DELETE CASCADE
);

CREATE INDEX idx_product_item_product ON product_item(product_id);
CREATE INDEX idx_product_item_active ON product_item(is_active);
```

---

#### **TABLE: `shopping_cart`**

```sql
CREATE TABLE shopping_cart (
  id                INTEGER PRIMARY KEY AUTO_INCREMENT,
  user_id           INTEGER UNIQUE NOT NULL,
  expires_at        TIMESTAMP NULL,
  created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  
  FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
);
```

---

#### **TABLE: `shopping_cart_item`**

```sql
CREATE TABLE shopping_cart_item (
  id                INTEGER PRIMARY KEY AUTO_INCREMENT,
  cart_id           INTEGER NOT NULL,
  product_item_id   INTEGER NOT NULL,
  quantity          INTEGER NOT NULL DEFAULT 1,
  created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  
  FOREIGN KEY (cart_id) REFERENCES shopping_cart(id) ON DELETE CASCADE,
  FOREIGN KEY (product_item_id) REFERENCES product_item(id) ON DELETE CASCADE,
  UNIQUE KEY unique_cart_item (cart_id, product_item_id)
);
```

---

#### **TABLE: `shop_order`**

**🔒 CRITICAL for Logic Flaw Labs**

```sql
CREATE TABLE shop_order (
  id                    INTEGER PRIMARY KEY AUTO_INCREMENT,
  user_id               INTEGER NOT NULL,
  order_number          VARCHAR(50) UNIQUE NOT NULL,
  
  -- Pricing Breakdown (IMPORTANT for price manipulation labs)
  subtotal              DECIMAL(10,2) NOT NULL,
  shipping_cost         DECIMAL(10,2) DEFAULT 0.00,
  tax_amount            DECIMAL(10,2) DEFAULT 0.00,
  discount_amount       DECIMAL(10,2) DEFAULT 0.00,
  final_total           DECIMAL(10,2) NOT NULL,
  
  -- Foreign Keys
  shipping_address_id   INTEGER NOT NULL,
  shipping_method_id    INTEGER NOT NULL,
  payment_method_id     INTEGER NOT NULL,
  order_status_id       INTEGER NOT NULL,
  
  -- Tracking
  tracking_number       VARCHAR(100) NULL,
  notes                 TEXT NULL,
  
  -- Timestamps
  created_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  paid_at               TIMESTAMP NULL,
  shipped_at            TIMESTAMP NULL,
  delivered_at          TIMESTAMP NULL,
  
  FOREIGN KEY (user_id) REFERENCES user(id),
  FOREIGN KEY (shipping_address_id) REFERENCES address(id),
  FOREIGN KEY (shipping_method_id) REFERENCES shipping_method(id),
  FOREIGN KEY (payment_method_id) REFERENCES payment_method(id),
  FOREIGN KEY (order_status_id) REFERENCES order_status(id)
);

CREATE INDEX idx_order_user ON shop_order(user_id);
CREATE INDEX idx_order_status ON shop_order(order_status_id);
CREATE UNIQUE INDEX idx_order_number ON shop_order(order_number);
```

---

#### **TABLE: `order_line`**

```sql
CREATE TABLE order_line (
  id                INTEGER PRIMARY KEY AUTO_INCREMENT,
  order_id          INTEGER NOT NULL,
  product_item_id   INTEGER NOT NULL,
  quantity          INTEGER NOT NULL,
  unit_price        DECIMAL(10,2) NOT NULL,
  total_price       DECIMAL(10,2) NOT NULL,
  
  -- Snapshot fields (in case product deleted)
  product_name      VARCHAR(255) NOT NULL,
  product_sku       VARCHAR(50) NOT NULL,
  
  created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  
  FOREIGN KEY (order_id) REFERENCES shop_order(id) ON DELETE CASCADE,
  FOREIGN KEY (product_item_id) REFERENCES product_item(id)
);

CREATE INDEX idx_order_line_order ON order_line(order_id);
```

---

#### **TABLE: `user_review`**

**🔒 CRITICAL for XSS Labs**

```sql
CREATE TABLE user_review (
  id                    INTEGER PRIMARY KEY AUTO_INCREMENT,
  user_id               INTEGER NOT NULL,
  product_id            INTEGER NOT NULL,
  order_id              INTEGER NULL,
  rating                INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
  title                 VARCHAR(200) NULL,
  comment               TEXT NULL,  -- 🔒 XSS injection point
  is_verified_purchase  BOOLEAN DEFAULT false,
  is_approved           BOOLEAN DEFAULT true,
  helpful_count         INTEGER DEFAULT 0,
  created_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  
  FOREIGN KEY (user_id) REFERENCES user(id),
  FOREIGN KEY (product_id) REFERENCES product(id) ON DELETE CASCADE,
  FOREIGN KEY (order_id) REFERENCES shop_order(id) ON DELETE SET NULL
);

CREATE INDEX idx_review_product ON user_review(product_id);
CREATE INDEX idx_review_user ON user_review(user_id);
CREATE INDEX idx_review_approved ON user_review(is_approved);
```

---

#### **TABLE: `promotion`**

**🔒 IMPORTANT for Logic Flaw Labs (coupon bypass)**

```sql
CREATE TABLE promotion (
  id                    INTEGER PRIMARY KEY AUTO_INCREMENT,
  code                  VARCHAR(50) UNIQUE NOT NULL,
  name                  VARCHAR(100) NOT NULL,
  description           TEXT NULL,
  discount_type         ENUM('percentage', 'fixed_amount') DEFAULT 'percentage',
  discount_value        DECIMAL(10,2) NOT NULL,
  minimum_order_amount  DECIMAL(10,2) NULL,
  max_discount_amount   DECIMAL(10,2) NULL,
  usage_limit           INTEGER NULL,
  usage_count           INTEGER DEFAULT 0,
  is_active             BOOLEAN DEFAULT true,
  start_date            TIMESTAMP NOT NULL,
  end_date              TIMESTAMP NOT NULL,
  created_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX idx_promotion_code ON promotion(code);
CREATE INDEX idx_promotion_active ON promotion(is_active);
CREATE INDEX idx_promotion_dates ON promotion(start_date, end_date);
```

---

#### **TABLE: `promotion_category`** (Junction table)

```sql
CREATE TABLE promotion_category (
  promotion_id      INTEGER NOT NULL,
  category_id       INTEGER NOT NULL,
  PRIMARY KEY (promotion_id, category_id),
  
  FOREIGN KEY (promotion_id) REFERENCES promotion(id) ON DELETE CASCADE,
  FOREIGN KEY (category_id) REFERENCES category(id) ON DELETE CASCADE
);
```

---

#### **REFERENCE TABLES**

```sql
-- payment_method
CREATE TABLE payment_method (
  id                        INTEGER PRIMARY KEY AUTO_INCREMENT,
  code                      VARCHAR(50) UNIQUE NOT NULL,
  method_name               VARCHAR(100) NOT NULL,
  description               TEXT NULL,
  is_active                 BOOLEAN DEFAULT true,
  processing_fee_percentage DECIMAL(5,2) DEFAULT 0.00
);

-- shipping_method
CREATE TABLE shipping_method (
  id                    INTEGER PRIMARY KEY AUTO_INCREMENT,
  code                  VARCHAR(50) UNIQUE NOT NULL,
  name                  VARCHAR(100) NOT NULL,
  description           TEXT NULL,
  price                 DECIMAL(10,2) NOT NULL,
  estimated_days_min    INTEGER NOT NULL,
  estimated_days_max    INTEGER NOT NULL,
  is_active             BOOLEAN DEFAULT true,
  created_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- order_status
CREATE TABLE order_status (
  id                INTEGER PRIMARY KEY AUTO_INCREMENT,
  code              VARCHAR(50) UNIQUE NOT NULL,
  display_name      VARCHAR(100) NOT NULL,
  description       TEXT NULL,
  color             VARCHAR(7) NULL,
  display_order     INTEGER DEFAULT 0
);
```

---

## 📊 **Relationships Summary**

```
user (1) ----< (M) user_token
user (1) ----< (M) user_security_log
user (1) ---- (1) user_profile
user (1) ---- (1) user_setting
user (1) ----< (M) user_address ----< (M) address
user (1) ---- (1) shopping_cart ----< (M) shopping_cart_item
user (1) ----< (M) shop_order
user (1) ----< (M) user_review

product (1) ----< (M) product_item
product (1) ----< (M) user_review
product (M) ----< (M) category (via parent_category_id)

shop_order (1) ----< (M) order_line
shop_order (M) ---- (1) order_status
shop_order (M) ---- (1) shipping_method
shop_order (M) ---- (1) payment_method
shop_order (M) ---- (1) address (shipping)

promotion (M) ----< (M) category (via promotion_category)
```

---

## ✅ **Implementation Checklist**

### **Phase 1: Core Tables (v1)**
- [ ] `user` (10 fields)
- [ ] `user_token` (extensible token management)
- [ ] `user_profile`
- [ ] `address`
- [ ] `user_address`
- [ ] `country`
- [ ] `product`
- [ ] `product_item`
- [ ] `category`
- [ ] `shopping_cart`
- [ ] `shopping_cart_item`
- [ ] `shop_order`
- [ ] `order_line`
- [ ] `user_review`
- [ ] `promotion`
- [ ] `promotion_category`
- [ ] `payment_method` (reference)
- [ ] `shipping_method` (reference)
- [ ] `order_status` (reference)

### **Phase 2: Advanced Tables (v2)**
- [ ] `user_security_log` (audit trail)
- [ ] `user_setting` (preferences)
- [ ] `variation` (product variants - optional)
- [ ] `variation_option` (optional)
- [ ] `product_configuration` (optional)

---

## 🎯 **Next Steps**

1. **Update your ERD tool** với schema này
2. **Export SQL script** (if possible)
3. **Show me the updated ERD** → Tôi sẽ generate Sequelize models
4. **Run migrations** → Setup database
5. **Start coding API!** 🚀

---

**Last Updated:** 2026-01-25  
**Version:** 2.0 - Modular Design
