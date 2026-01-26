-- VulLab E-Commerce Database Schema
-- Compatible with PostgreSQL

-- ===========================
-- USER MODULE
-- ===========================

CREATE TABLE "user" (
  id SERIAL PRIMARY KEY,
  username VARCHAR(50) UNIQUE NOT NULL,
  email VARCHAR(100) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  role VARCHAR(20) DEFAULT 'user' NOT NULL,
  is_active BOOLEAN DEFAULT true,
  is_email_verified BOOLEAN DEFAULT false,
  last_login_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_user_email ON "user"(email);
CREATE INDEX idx_user_username ON "user"(username);
CREATE INDEX idx_user_role ON "user"(role);

CREATE TABLE user_token (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  token_type VARCHAR(50) NOT NULL,
  token_value VARCHAR(255) NOT NULL,
  expires_at TIMESTAMP,
  is_used BOOLEAN DEFAULT false,
  used_at TIMESTAMP,
  ip_address VARCHAR(45),
  user_agent TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_token_value ON user_token(token_value);
CREATE INDEX idx_user_type ON user_token(user_id, token_type);
CREATE INDEX idx_token_expires ON user_token(expires_at);

CREATE TABLE user_profile (
  id SERIAL PRIMARY KEY,
  user_id INTEGER UNIQUE NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  first_name VARCHAR(50),
  last_name VARCHAR(50),
  phone_number VARCHAR(20),
  date_of_birth DATE,
  avatar_url VARCHAR(255),
  bio TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_security_log (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES "user"(id) ON DELETE SET NULL,
  event_type VARCHAR(50) NOT NULL,
  ip_address VARCHAR(45),
  user_agent TEXT,
  metadata JSONB,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_log_user_event ON user_security_log(user_id, event_type);
CREATE INDEX idx_log_created ON user_security_log(created_at);

CREATE TABLE user_setting (
  id SERIAL PRIMARY KEY,
  user_id INTEGER UNIQUE NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  enable_2fa BOOLEAN DEFAULT false,
  login_notifications BOOLEAN DEFAULT true,
  profile_visibility VARCHAR(20) DEFAULT 'public',
  preferences JSONB,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ===========================
-- ADDRESS MODULE
-- ===========================

CREATE TABLE country (
  id SERIAL PRIMARY KEY,
  country_name VARCHAR(100) UNIQUE NOT NULL,
  country_code VARCHAR(3) UNIQUE NOT NULL
);

CREATE TABLE address (
  id SERIAL PRIMARY KEY,
  street_address VARCHAR(255) NOT NULL,
  street_address_2 VARCHAR(255),
  city VARCHAR(100) NOT NULL,
  state_province VARCHAR(100),
  postal_code VARCHAR(20) NOT NULL,
  country_id INTEGER NOT NULL REFERENCES country(id),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_address (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  address_id INTEGER NOT NULL REFERENCES address(id) ON DELETE CASCADE,
  is_default BOOLEAN DEFAULT false,
  address_type VARCHAR(20) DEFAULT 'both',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, address_id)
);

-- ===========================
-- PRODUCT MODULE
-- ===========================

CREATE TABLE category (
  id SERIAL PRIMARY KEY,
  parent_category_id INTEGER REFERENCES category(id) ON DELETE SET NULL,
  category_name VARCHAR(100) NOT NULL,
  slug VARCHAR(100) UNIQUE NOT NULL,
  description TEXT,
  is_active BOOLEAN DEFAULT true,
  display_order INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE product (
  id SERIAL PRIMARY KEY,
  category_id INTEGER NOT NULL REFERENCES category(id),
  name VARCHAR(255) NOT NULL,
  description TEXT,
  product_image VARCHAR(255),
  sku VARCHAR(50) UNIQUE,
  is_published BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_product_category ON product(category_id);
CREATE INDEX idx_product_published ON product(is_published);
CREATE INDEX idx_product_sku ON product(sku);

CREATE TABLE product_item (
  id SERIAL PRIMARY KEY,
  product_id INTEGER NOT NULL REFERENCES product(id) ON DELETE CASCADE,
  sku VARCHAR(50) UNIQUE NOT NULL,
  price DECIMAL(10,2) NOT NULL,
  original_price DECIMAL(10,2),
  quantity_in_stock INTEGER DEFAULT 0 NOT NULL,
  product_image VARCHAR(255),
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_product_item_product ON product_item(product_id);
CREATE INDEX idx_product_item_active ON product_item(is_active);

CREATE TABLE user_review (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES "user"(id),
  product_id INTEGER NOT NULL REFERENCES product(id) ON DELETE CASCADE,
  order_id INTEGER REFERENCES shop_order(id) ON DELETE SET NULL,
  rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
  title VARCHAR(200),
  comment TEXT,
  is_verified_purchase BOOLEAN DEFAULT false,
  is_approved BOOLEAN DEFAULT true,
  helpful_count INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_review_product ON user_review(product_id);
CREATE INDEX idx_review_user ON user_review(user_id);

-- ===========================
-- CART MODULE
-- ===========================

CREATE TABLE shopping_cart (
  id SERIAL PRIMARY KEY,
  user_id INTEGER UNIQUE NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  expires_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE shopping_cart_item (
  id SERIAL PRIMARY KEY,
  cart_id INTEGER NOT NULL REFERENCES shopping_cart(id) ON DELETE CASCADE,
  product_item_id INTEGER NOT NULL REFERENCES product_item(id),
  quantity INTEGER DEFAULT 1 NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(cart_id, product_item_id)
);

-- ===========================
-- ORDER MODULE
-- ===========================

CREATE TABLE order_status (
  id SERIAL PRIMARY KEY,
  code VARCHAR(50) UNIQUE NOT NULL,
  display_name VARCHAR(100) NOT NULL,
  description TEXT,
  color VARCHAR(7),
  display_order INTEGER DEFAULT 0
);

CREATE TABLE shipping_method (
  id SERIAL PRIMARY KEY,
  code VARCHAR(50) UNIQUE NOT NULL,
  name VARCHAR(100) NOT NULL,
  description TEXT,
  price DECIMAL(10,2) NOT NULL,
  estimated_days_min INTEGER NOT NULL,
  estimated_days_max INTEGER NOT NULL,
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE payment_method (
  id SERIAL PRIMARY KEY,
  code VARCHAR(50) UNIQUE NOT NULL,
  method_name VARCHAR(100) NOT NULL,
  description TEXT,
  is_active BOOLEAN DEFAULT true,
  processing_fee_percentage DECIMAL(5,2) DEFAULT 0.00
);

CREATE TABLE shop_order (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES "user"(id),
  order_number VARCHAR(50) UNIQUE NOT NULL,
  subtotal DECIMAL(10,2) NOT NULL,
  shipping_cost DECIMAL(10,2) DEFAULT 0.00,
  tax_amount DECIMAL(10,2) DEFAULT 0.00,
  discount_amount DECIMAL(10,2) DEFAULT 0.00,
  final_total DECIMAL(10,2) NOT NULL,
  shipping_address_id INTEGER NOT NULL REFERENCES address(id),
  shipping_method_id INTEGER NOT NULL REFERENCES shipping_method(id),
  payment_method_id INTEGER NOT NULL REFERENCES payment_method(id),
  order_status_id INTEGER NOT NULL REFERENCES order_status(id),
  tracking_number VARCHAR(100),
  notes TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  paid_at TIMESTAMP,
  shipped_at TIMESTAMP,
  delivered_at TIMESTAMP
);

CREATE INDEX idx_order_user ON shop_order(user_id);
CREATE INDEX idx_order_status ON shop_order(order_status_id);
CREATE INDEX idx_order_number ON shop_order(order_number);

CREATE TABLE order_line (
  id SERIAL PRIMARY KEY,
  order_id INTEGER NOT NULL REFERENCES shop_order(id) ON DELETE CASCADE,
  product_item_id INTEGER NOT NULL REFERENCES product_item(id),
  quantity INTEGER NOT NULL,
  unit_price DECIMAL(10,2) NOT NULL,
  total_price DECIMAL(10,2) NOT NULL,
  product_name VARCHAR(255) NOT NULL,
  product_sku VARCHAR(50) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_order_line_order ON order_line(order_id);

-- ===========================
-- PROMOTION MODULE
-- ===========================

CREATE TABLE promotion (
  id SERIAL PRIMARY KEY,
  code VARCHAR(50) UNIQUE NOT NULL,
  name VARCHAR(100) NOT NULL,
  description TEXT,
  discount_type VARCHAR(20) DEFAULT 'percentage',
  discount_value DECIMAL(10,2) NOT NULL,
  minimum_order_amount DECIMAL(10,2),
  max_discount_amount DECIMAL(10,2),
  usage_limit INTEGER,
  usage_count INTEGER DEFAULT 0,
  is_active BOOLEAN DEFAULT true,
  start_date TIMESTAMP NOT NULL,
  end_date TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_promotion_code ON promotion(code);
CREATE INDEX idx_promotion_active ON promotion(is_active);

CREATE TABLE promotion_category (
  promotion_id INTEGER REFERENCES promotion(id) ON DELETE CASCADE,
  category_id INTEGER REFERENCES category(id) ON DELETE CASCADE,
  PRIMARY KEY (promotion_id, category_id)
);

-- ===========================
-- OPTIONAL: PRODUCT VARIATIONS
-- ===========================

CREATE TABLE variation (
  id SERIAL PRIMARY KEY,
  category_id INTEGER NOT NULL REFERENCES category(id),
  name VARCHAR(100) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE variation_option (
  id SERIAL PRIMARY KEY,
  variation_id INTEGER NOT NULL REFERENCES variation(id) ON DELETE CASCADE,
  value VARCHAR(100) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE product_configuration (
  product_item_id INTEGER REFERENCES product_item(id) ON DELETE CASCADE,
  variation_option_id INTEGER REFERENCES variation_option(id) ON DELETE CASCADE,
  PRIMARY KEY (product_item_id, variation_option_id)
);
