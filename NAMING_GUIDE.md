# 📐 VulLab - Naming Conventions & Coding Standards

> **Mục đích:** Đảm bảo tính nhất quán trong codebase, giúp dễ đọc, dễ maintain và dễ collaborate.

---

## 📑 Table of Contents

1. [File & Folder Names](#1-file--folder-names)
2. [Database Naming](#2-database-naming)
3. [Sequelize Models](#3-sequelize-models)
4. [Variables & Constants](#4-variables--constants)
5. [Functions & Methods](#5-functions--methods)
6. [Routes & Endpoints](#6-routes--endpoints)
7. [Controllers & Services](#7-controllers--services)
8. [Middleware](#8-middleware)
9. [Test Files](#9-test-files)
10. [Environment Variables](#10-environment-variables)
11. [Vulnerable Endpoints](#11-vulnerable-endpoints-naming)
12. [Quick Reference Table](#quick-reference-table)

---

## 1. File & Folder Names

### ✅ Convention: `kebab-case.type.js`

```
src/
├── models/
│   ├── user.model.js
│   ├── product.model.js
│   └── shopping-cart.model.js
├── controllers/
│   ├── auth.controller.js
│   ├── product.controller.js
│   └── order.controller.js
├── services/
│   ├── auth.service.js
│   ├── payment.service.js
│   └── notification.service.js
├── routes/
│   ├── auth.routes.js
│   ├── product.routes.js
│   └── shopping-cart.routes.js
├── middlewares/
│   ├── authenticate.middleware.js
│   └── validate-input.middleware.js
└── utils/
    ├── string-helper.util.js
    └── date-formatter.util.js
```

### ❌ Tránh

```javascript
// ❌ PascalCase
User.js
ProductController.js

// ❌ camelCase
userModel.js
authService.js

// ❌ snake_case
user_model.js
auth_service.js
```

### 📝 Lý do
- **Lowercase + kebab-case:** Tránh conflict giữa OS (Windows không phân biệt hoa/thường)
- **Suffix `.type.js`:** Identify mục đích file ngay lập tức
- **Dễ đọc:** Clear separation giữa các từ

---

## 2. Database Naming

### ✅ Tables: `snake_case` (singular)

```sql
-- ✅ ĐÚNG
user
product
shop_order
shopping_cart
payment_method
product_item
user_review

-- ❌ SAI
Users               -- số nhiều
shopOrder           -- camelCase
PaymentMethod       -- PascalCase
product-item        -- kebab-case
```

### ✅ Columns: `snake_case`

```sql
-- ✅ ĐÚNG
user_id
created_at
updated_at
first_name
phone_number
is_active
total_price

-- ❌ SAI
userId              -- camelCase
CreatedAt           -- PascalCase
first-name          -- kebab-case
```

### 📝 Lý do
- **snake_case:** Convention chuẩn của SQL và PostgreSQL
- **Singular tables:** Mỗi row đại diện cho 1 entity
- **Descriptive:** Tên rõ ràng, self-documenting

---

## 3. Sequelize Models

### ✅ Convention: `PascalCase` (singular)

```javascript
// ✅ File: user.model.js
const User = sequelize.define('User', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  firstName: {                    // camelCase trong model
    type: DataTypes.STRING,
    field: 'first_name'           // Map tới column snake_case
  },
  isActive: {
    type: DataTypes.BOOLEAN,
    field: 'is_active',
    defaultValue: true
  }
}, {
  tableName: 'user',              // Map tới table snake_case
  underscored: true,              // Auto convert camelCase -> snake_case
  timestamps: true
});

module.exports = User;
```

### ✅ Model Associations

```javascript
// File: models/index.js
const User = require('./user.model');
const ShopOrder = require('./shop-order.model');
const Product = require('./product.model');
const Category = require('./category.model');

// One-to-Many
User.hasMany(ShopOrder, { foreignKey: 'user_id', as: 'orders' });
ShopOrder.belongsTo(User, { foreignKey: 'user_id', as: 'user' });

// Many-to-Many
Product.belongsToMany(Category, { 
  through: 'product_category', 
  foreignKey: 'product_id' 
});
Category.belongsToMany(Product, { 
  through: 'product_category', 
  foreignKey: 'category_id' 
});

module.exports = { User, ShopOrder, Product, Category };
```

### ❌ Tránh

```javascript
// ❌ lowercase
const user = sequelize.define('user', ...);

// ❌ số nhiều
const Users = sequelize.define('Users', ...);

// ❌ Không map field
firstName: DataTypes.STRING  // Sẽ tìm column 'firstName' thay vì 'first_name'
```

---

## 4. Variables & Constants

### ✅ Variables: `camelCase`

```javascript
// ✅ ĐÚNG
const userId = req.params.id;
const productList = await Product.findAll();
const isAuthenticated = checkAuth(token);
let currentPage = 1;
let totalAmount = 0;

// Function parameters
function createOrder(userId, productItems, shippingAddress) {
  const orderTotal = calculateTotal(productItems);
  const discountAmount = applyDiscount(orderTotal);
  return orderTotal - discountAmount;
}

// ❌ SAI
const user_id = req.params.id;        // snake_case
const ProductList = [];               // PascalCase
const is_authenticated = true;        // snake_case
```

### ✅ Constants: `SCREAMING_SNAKE_CASE`

```javascript
// ✅ ĐÚNG
const MAX_LOGIN_ATTEMPTS = 5;
const JWT_EXPIRES_IN = '24h';
const DEFAULT_PAGE_SIZE = 20;
const API_VERSION = 'v1';

const ORDER_STATUS = {
  PENDING: 'pending',
  PROCESSING: 'processing',
  SHIPPED: 'shipped',
  DELIVERED: 'delivered',
  CANCELLED: 'cancelled'
};

const USER_ROLES = {
  ADMIN: 'admin',
  USER: 'user',
  GUEST: 'guest'
};

// ❌ SAI
const maxLoginAttempts = 5;           // camelCase
const JwtExpiresIn = '24h';           // PascalCase
const orderStatus = { ... };          // camelCase
```

---

## 5. Functions & Methods

### ✅ Convention: `camelCase` với động từ đầu tiên

```javascript
// ✅ CRUD Operations
async getAllProducts() { ... }
async getProductById(id) { ... }
async getUserByEmail(email) { ... }
async createOrder(orderData) { ... }
async updateUserProfile(userId, data) { ... }
async deleteProduct(productId) { ... }

// ✅ Business Logic
async calculateTotalPrice(items) { ... }
async validatePaymentMethod(method) { ... }
async processPayment(orderId, paymentData) { ... }
async generateInvoice(orderId) { ... }
async sendConfirmationEmail(userId) { ... }

// ✅ Boolean Checks (return true/false)
function isValidEmail(email) { ... }
function isAdmin(user) { ... }
function hasPermission(user, resource) { ... }
function canAccessOrder(userId, orderId) { ... }

// ✅ Utility/Helper Functions
function sanitizeInput(input) { ... }
function formatCurrency(amount) { ... }
function parseQueryParams(query) { ... }
function generateToken(payload) { ... }
```

### 📋 Verb Guidelines

| Operation | Verb | Example |
|-----------|------|---------|
| **Read All** | `getAll...`, `findAll...`, `list...` | `getAllProducts()` |
| **Read One** | `getById...`, `findById...`, `getBy...` | `getUserById()` |
| **Create** | `create...`, `add...`, `insert...` | `createOrder()` |
| **Update** | `update...`, `modify...`, `edit...` | `updateProfile()` |
| **Delete** | `delete...`, `remove...`, `destroy...` | `deleteProduct()` |
| **Validation** | `validate...`, `check...`, `verify...` | `validateEmail()` |
| **Calculation** | `calculate...`, `compute...` | `calculateTotal()` |
| **Processing** | `process...`, `handle...` | `processPayment()` |
| **Boolean** | `is...`, `has...`, `can...`, `should...` | `isActive()` |

### ❌ Tránh

```javascript
// ❌ PascalCase
function GetAllProducts() { ... }

// ❌ snake_case
function get_user_by_id() { ... }

// ❌ Quá ngắn, thiếu context
function get() { ... }
function update() { ... }
function data() { ... }

// ❌ Không có động từ
function productList() { ... }      // Nên: getProductList()
function userProfile() { ... }      // Nên: getUserProfile()
```

---

## 6. Routes & Endpoints

### ✅ RESTful Convention: `kebab-case`

```javascript
// ✅ Basic CRUD
GET    /api/products                    // List all products
GET    /api/products/:id                // Get single product
POST   /api/products                    // Create product
PUT    /api/products/:id                // Update product (full)
PATCH  /api/products/:id                // Update product (partial)
DELETE /api/products/:id                // Delete product

// ✅ Nested Resources
GET    /api/users/:userId/orders        // Get user's orders
POST   /api/users/:userId/addresses     // Add address to user
GET    /api/products/:productId/reviews // Get product reviews

// ✅ Action-based (Non-CRUD)
POST   /api/auth/login
POST   /api/auth/logout
POST   /api/auth/reset-password
POST   /api/auth/verify-email

GET    /api/cart/checkout
POST   /api/orders/:orderId/cancel
POST   /api/products/:productId/favorite

// ✅ Search & Filtering
GET    /api/products/search?q=keyword
GET    /api/products?category=electronics&sort=price
GET    /api/orders?status=pending&page=1

// ✅ Versioning
GET    /api/v1/products
GET    /api/v2/products
```

### ✅ Route Parameters

```javascript
// ✅ Descriptive parameter names
/api/users/:userId/orders/:orderId
/api/products/:productId/variations/:variationId

// ❌ Tránh generic names
/api/users/:id/orders/:id           // Confusing!
```

### ❌ Tránh

```javascript
// ❌ Động từ trong URL (không RESTful)
GET  /api/getProducts
POST /api/createOrder
GET  /api/fetchUserProfile

// ❌ PascalCase
GET  /api/Products
GET  /api/UserOrders

// ❌ snake_case
GET  /api/product_list
GET  /api/user_orders

// ❌ camelCase
GET  /api/userOrders
GET  /api/productDetails
```

---

## 7. Controllers & Services

### ✅ Controllers: Export object với methods

```javascript
// File: product.controller.js

// ✅ Option 1: Named exports
exports.getAllProducts = async (req, res) => {
  try {
    const products = await productService.getAllProducts();
    res.json({ success: true, data: products });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

exports.getProductById = async (req, res) => {
  try {
    const product = await productService.getProductById(req.params.id);
    if (!product) {
      return res.status(404).json({ success: false, message: 'Product not found' });
    }
    res.json({ success: true, data: product });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

// ✅ Option 2: Module exports object
module.exports = {
  getAllProducts: async (req, res) => { ... },
  getProductById: async (req, res) => { ... },
  createProduct: async (req, res) => { ... }
};
```

### ✅ Services: Business logic layer

```javascript
// File: product.service.js

class ProductService {
  async getAllProducts(filters = {}) {
    const { category, minPrice, maxPrice } = filters;
    const where = {};
    
    if (category) where.category_id = category;
    if (minPrice) where.price = { [Op.gte]: minPrice };
    if (maxPrice) where.price = { ...where.price, [Op.lte]: maxPrice };
    
    return await Product.findAll({ where });
  }

  async getProductById(id) {
    return await Product.findByPk(id, {
      include: ['category', 'variations']
    });
  }

  async createProduct(productData) {
    return await Product.create(productData);
  }

  async updateProduct(id, updateData) {
    const product = await this.getProductById(id);
    if (!product) throw new Error('Product not found');
    return await product.update(updateData);
  }
}

module.exports = new ProductService();

// Usage trong controller:
const productService = require('../services/product.service');
```

---

## 8. Middleware

### ✅ Convention: `camelCase` với mô tả rõ ràng

```javascript
// File: authenticate.middleware.js

function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
}

function validateRegistration(req, res, next) {
  const { username, email, password } = req.body;
  const errors = [];
  
  if (!username || username.length < 3) {
    errors.push('Username must be at least 3 characters');
  }
  if (!isValidEmail(email)) {
    errors.push('Invalid email format');
  }
  if (password.length < 8) {
    errors.push('Password must be at least 8 characters');
  }
  
  if (errors.length > 0) {
    return res.status(400).json({ errors });
  }
  next();
}

module.exports = {
  authenticateToken,
  requireAdmin,
  validateRegistration
};
```

### ✅ Usage trong Routes

```javascript
const { authenticateToken, requireAdmin } = require('../middlewares/authenticate.middleware');

// Apply middleware
router.get('/profile', authenticateToken, userController.getProfile);
router.post('/products', authenticateToken, requireAdmin, productController.createProduct);
```

---

## 9. Test Files

### ✅ Convention: `filename.test.js`

```
tests/
├── unit/
│   ├── models/
│   │   ├── user.model.test.js
│   │   └── product.model.test.js
│   ├── services/
│   │   ├── auth.service.test.js
│   │   └── product.service.test.js
│   └── utils/
│       └── string-helper.util.test.js
├── integration/
│   ├── auth.routes.test.js
│   ├── product.routes.test.js
│   └── order.routes.test.js
└── e2e/
    └── checkout-flow.test.js
```

### ✅ Test Case Naming

```javascript
// File: user.model.test.js

describe('User Model', () => {
  describe('create', () => {
    it('should create a new user with valid data', async () => { ... });
    it('should hash password before saving', async () => { ... });
    it('should throw error if email already exists', async () => { ... });
  });

  describe('findByEmail', () => {
    it('should return user when email exists', async () => { ... });
    it('should return null when email does not exist', async () => { ... });
  });
});
```

---

## 10. Environment Variables

### ✅ Convention: `SCREAMING_SNAKE_CASE`

```bash
# File: .env

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=vullab_db
DB_USER=postgres
DB_PASSWORD=your_password_here
DB_DIALECT=postgres

# Server Configuration
NODE_ENV=development
PORT=3000
API_VERSION=v1

# JWT Configuration
JWT_SECRET=your-super-secret-key-change-this
JWT_EXPIRES_IN=24h
JWT_REFRESH_EXPIRES_IN=7d

# Security
BCRYPT_ROUNDS=10
MAX_LOGIN_ATTEMPTS=5
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# Features
ENABLE_RATE_LIMITING=true
ENABLE_CORS=true
ENABLE_LOGGING=true

# Email (optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
```

### ✅ Usage trong Code

```javascript
// File: config/database.js
module.exports = {
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  username: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  dialect: process.env.DB_DIALECT
};
```

---

## 11. Vulnerable Endpoints Naming

### ✅ Convention: Clear prefix + vulnerability type

```javascript
// Routes Structure
src/routes/vuln/
├── sqli.routes.js              // SQL Injection labs
├── xss.routes.js               // Cross-Site Scripting labs
├── idor.routes.js              // Insecure Direct Object Reference
├── auth-bypass.routes.js       // Authentication bypass
├── logic-flaws.routes.js       // Business logic vulnerabilities
└── xxe.routes.js               // XML External Entity

// Endpoint Examples
GET  /api/vuln/sqli/search-basic           // Basic SQL Injection
GET  /api/vuln/sqli/search-blind           // Blind SQL Injection
POST /api/vuln/sqli/login                  // SQL Injection in Login

GET  /api/vuln/xss/reflected               // Reflected XSS
POST /api/vuln/xss/stored                  // Stored XSS
GET  /api/vuln/xss/dom                     // DOM-based XSS

GET  /api/vuln/idor/order/:id              // Order IDOR
GET  /api/vuln/idor/user-profile/:id       // Profile IDOR

POST /api/vuln/auth/weak-password          // Weak password policy
POST /api/vuln/auth/sql-bypass             // SQLi auth bypass

GET  /api/vuln/logic/price-manipulation    // Price manipulation
POST /api/vuln/logic/negative-quantity     // Negative quantity bug
```

### ✅ Controller Naming

```javascript
// File: sqli.controller.js

exports.searchBasic = async (req, res) => {
  // VULNERABLE: Basic SQL Injection
  const query = `SELECT * FROM product WHERE name LIKE '%${req.query.q}%'`;
  // ...
};

exports.searchBlind = async (req, res) => {
  // VULNERABLE: Blind SQL Injection
  // ...
};

exports.loginVulnerable = async (req, res) => {
  // VULNERABLE: SQL Injection in login
  // ...
};
```

### ✅ Lab Documentation

```javascript
// Add hints in response
res.json({
  success: true,
  data: results,
  lab: {
    name: 'Basic SQL Injection',
    difficulty: 'Easy',
    hint: 'Try payload: \' OR 1=1--',
    objective: 'Extract all products including unpublished ones'
  }
});
```

---

## Quick Reference Table

| Element | Convention | Example | File Extension |
|---------|------------|---------|----------------|
| **Files** | `kebab-case.type.ext` | `user.model.js` | `.js` |
| **Folders** | `kebab-case` | `shopping-cart/` | - |
| **DB Tables** | `snake_case` (singular) | `shop_order` | - |
| **DB Columns** | `snake_case` | `created_at` | - |
| **Models** | `PascalCase` (singular) | `ShopOrder` | - |
| **Variables** | `camelCase` | `userId` | - |
| **Constants** | `SCREAMING_SNAKE_CASE` | `MAX_ATTEMPTS` | - |
| **Functions** | `camelCase` (verb first) | `getUserById()` | - |
| **Classes** | `PascalCase` | `ProductService` | - |
| **Routes** | `kebab-case` | `/api/shop-order` | - |
| **Env Vars** | `SCREAMING_SNAKE_CASE` | `DB_HOST` | - |
| **Middleware** | `camelCase` | `authenticateToken` | - |
| **Tests** | `filename.test.js` | `user.test.js` | `.test.js` |

---

## 💡 Best Practices

### 1. **Tránh viết tắt khó hiểu**
```javascript
// ❌ SAI
const uid = req.params.id;
const prod = await Product.findByPk(id);
const addr = user.address;

// ✅ ĐÚNG
const userId = req.params.id;
const product = await Product.findByPk(id);
const address = user.address;
```

### 2. **Động từ rõ ràng**
```javascript
// ❌ SAI
function total(items) { ... }
function check(email) { ... }
function data() { ... }

// ✅ ĐÚNG
function calculateTotal(items) { ... }
function validateEmail(email) { ... }
function getUserData() { ... }
```

### 3. **Boolean prefix**
```javascript
// ❌ SAI
const active = user.status === 'active';
const admin = user.role === 'admin';
const permission = checkPermission(user);

// ✅ ĐÚNG
const isActive = user.status === 'active';
const isAdmin = user.role === 'admin';
const hasPermission = checkPermission(user);
```

### 4. **Consistent naming trong cùng 1 feature**
```javascript
// ✅ ĐÚNG - Nhất quán
getAllProducts()
getProductById()
createProduct()
updateProduct()
deleteProduct()

// ❌ SAI - Không nhất quán
getAllProducts()
fetchProductById()      // Dùng 'fetch' thay vì 'get'
addProduct()            // Dùng 'add' thay vì 'create'
modifyProduct()         // Dùng 'modify' thay vì 'update'
removeProduct()         // Dùng 'remove' thay vì 'delete'
```

### 5. **Self-documenting code**
```javascript
// ❌ SAI - Cần comment để hiểu
// Get users created in the last 30 days
const users = await User.findAll({ where: { created_at: { [Op.gte]: new Date(Date.now() - 30*24*60*60*1000) } } });

// ✅ ĐÚNG - Tên hàm đã self-explaining
const recentUsers = await getRecentlyCreatedUsers(30);

function getRecentlyCreatedUsers(days) {
  const dateThreshold = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  return User.findAll({ 
    where: { created_at: { [Op.gte]: dateThreshold } } 
  });
}
```

---

## 🔍 Common Mistakes to Avoid

| ❌ Mistake | ✅ Correct | Reason |
|-----------|-----------|---------|
| `getUserData()` returning `null` | `getUserData()` returns object or throws error | Functions should have predictable return types |
| `is_admin` (snake_case) | `isAdmin` (camelCase) | Follow JavaScript convention |
| `/api/getUsers` | `/api/users` (GET) | RESTful - method in HTTP verb, not URL |
| `user_id` in JavaScript | `userId` in JS, `user_id` in DB | Different conventions for different contexts |
| `MAX_login_attempts` | `MAX_LOGIN_ATTEMPTS` | All caps for constants |
| `UserController.js` | `user.controller.js` | File names should be lowercase |

---

## 📚 Additional Resources

- [Airbnb JavaScript Style Guide](https://github.com/airbnb/javascript)
- [Google JavaScript Style Guide](https://google.github.io/styleguide/jsguide.html)
- [RESTful API Naming Conventions](https://restfulapi.net/resource-naming/)
- [Sequelize Docs - Naming Strategies](https://sequelize.org/docs/v6/other-topics/naming-strategies/)

---

**Last Updated:** 2026-01-25  
**Maintained by:** VulLab Team

> 💡 **Tip:** Lưu file này và refer back thường xuyên khi code. Consistency là chìa khóa của một codebase clean và maintainable!
