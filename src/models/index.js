const { sequelize } = require('../config/database.config');

const { User } = require('./user/user.model');
const { UserProfile } = require('./user/user_profile.model');
const { UserToken } = require('./user/user_token.model');
const { UserSecurityLog } = require('./user/user_security_log.model');
const { UserSetting } = require('./user/user_setting.model');
const { LoginAttempt } = require('./user/login-attempt.model');
const { AuthToken } = require('./user/auth_token.model');
const { Address } = require('./shared/address.model');
const { UserAddress } = require('./shared/user_address.model');
const { Country } = require('./shared/country.model');
const { Category } = require('./product/category.model');
const { Product } = require('./product/product.model');
const { ProductItem } = require('./product/product-item.model');
const { UserReview } = require('./product/user-review.model');
const { ShoppingCart } = require('./cart/shopping-cart.model');
const { ShoppingCartItem } = require('./cart/shopping-cart-item.model');
const { OrderStatus } = require('./order/order-status.model');
const { ShippingMethod } = require('./order/shipping-method.model');
const { PaymentMethod } = require('./order/payment-method.model');
const { ShopOrder } = require('./order/shop-order.model');
const { OrderLine } = require('./order/order-line.model');
const { Promotion } = require('./marketing/promotion.model');
const { PromotionCategory } = require('./marketing/promotion-category.model');

User.hasOne(UserProfile, { foreignKey: 'userId', as: 'profile' });
UserProfile.belongsTo(User, { foreignKey: 'userId', as: 'user' });

User.hasMany(UserToken, { foreignKey: 'userId', as: 'tokens' });
UserToken.belongsTo(User, { foreignKey: 'userId', as: 'user' });

User.hasMany(AuthToken, { foreignKey: 'userId', as: 'authTokens' });
AuthToken.belongsTo(User, { foreignKey: 'userId', as: 'user' });

User.hasMany(UserSecurityLog, { foreignKey: 'userId', as: 'securityLogs' });
UserSecurityLog.belongsTo(User, { foreignKey: 'userId', as: 'user' });

User.hasOne(UserSetting, { foreignKey: 'userId', as: 'settings' });
UserSetting.belongsTo(User, { foreignKey: 'userId', as: 'user' });

User.belongsToMany(Address, { through: UserAddress, foreignKey: 'userId', otherKey: 'addressId', as: 'addresses' });
Address.belongsToMany(User, { through: UserAddress, foreignKey: 'addressId', otherKey: 'userId', as: 'users' });

User.hasMany(UserAddress, { foreignKey: 'userId', as: 'userAddresses' });
UserAddress.belongsTo(User, { foreignKey: 'userId', as: 'user' });

Address.hasMany(UserAddress, { foreignKey: 'addressId', as: 'addressUsers' });
UserAddress.belongsTo(Address, { foreignKey: 'addressId', as: 'address' });

Country.hasMany(Address, { foreignKey: 'countryId', as: 'addresses' });
Address.belongsTo(Country, { foreignKey: 'countryId', as: 'country' });


// --- Product Associations ---
Category.hasMany(Category, { foreignKey: 'parentCategoryId', as: 'children' });
Category.belongsTo(Category, { foreignKey: 'parentCategoryId', as: 'parent' });

Category.hasMany(Product, { foreignKey: 'categoryId', as: 'products' });
Product.belongsTo(Category, { foreignKey: 'categoryId', as: 'category' });

Product.hasMany(ProductItem, { foreignKey: 'productId', as: 'items' });
ProductItem.belongsTo(Product, { foreignKey: 'productId', as: 'product' });

Product.hasMany(UserReview, { foreignKey: 'productId', as: 'reviews' });
UserReview.belongsTo(Product, { foreignKey: 'productId', as: 'product' });
User.hasMany(UserReview, { foreignKey: 'userId', as: 'reviews' });
UserReview.belongsTo(User, { foreignKey: 'userId', as: 'user' });


// --- Cart Associations ---
User.hasOne(ShoppingCart, { foreignKey: 'userId', as: 'cart' });
ShoppingCart.belongsTo(User, { foreignKey: 'userId', as: 'user' });

ShoppingCart.belongsToMany(ProductItem, { through: ShoppingCartItem, foreignKey: 'cartId', otherKey: 'productItemId', as: 'items' });
ProductItem.belongsToMany(ShoppingCart, { through: ShoppingCartItem, foreignKey: 'productItemId', otherKey: 'cartId', as: 'carts' });

ShoppingCart.hasMany(ShoppingCartItem, { foreignKey: 'cartId', as: 'cartItems' });
ShoppingCartItem.belongsTo(ShoppingCart, { foreignKey: 'cartId', as: 'cart' });
ProductItem.hasMany(ShoppingCartItem, { foreignKey: 'productItemId', as: 'cartItemEntries' });
ShoppingCartItem.belongsTo(ProductItem, { foreignKey: 'productItemId', as: 'productItem' });


// --- Order Associations ---
User.hasMany(ShopOrder, { foreignKey: 'userId', as: 'orders' });
ShopOrder.belongsTo(User, { foreignKey: 'userId', as: 'user' });

OrderStatus.hasMany(ShopOrder, { foreignKey: 'orderStatusId', as: 'orders' });
ShopOrder.belongsTo(OrderStatus, { foreignKey: 'orderStatusId', as: 'status' });

ShippingMethod.hasMany(ShopOrder, { foreignKey: 'shippingMethodId', as: 'orders' });
ShopOrder.belongsTo(ShippingMethod, { foreignKey: 'shippingMethodId', as: 'shippingMethod' });

PaymentMethod.hasMany(ShopOrder, { foreignKey: 'paymentMethodId', as: 'orders' });
ShopOrder.belongsTo(PaymentMethod, { foreignKey: 'paymentMethodId', as: 'paymentMethod' });

Address.hasMany(ShopOrder, { foreignKey: 'shippingAddressId', as: 'shippingOrders' });
ShopOrder.belongsTo(Address, { foreignKey: 'shippingAddressId', as: 'shippingAddress' });

ShopOrder.hasMany(OrderLine, { foreignKey: 'orderId', as: 'lines' });
OrderLine.belongsTo(ShopOrder, { foreignKey: 'orderId', as: 'order' });

ProductItem.hasMany(OrderLine, { foreignKey: 'productItemId', as: 'orderLines' });
OrderLine.belongsTo(ProductItem, { foreignKey: 'productItemId', as: 'productItem' });


// --- Marketing Associations ---
Category.belongsToMany(Promotion, { through: PromotionCategory, foreignKey: 'categoryId', otherKey: 'promotionId', as: 'promotions' });
Promotion.belongsToMany(Category, { through: PromotionCategory, foreignKey: 'promotionId', otherKey: 'categoryId', as: 'categories' });


module.exports = {
    sequelize,
    User, UserProfile, UserToken, UserSecurityLog, UserSetting, LoginAttempt, AuthToken,
    Address, UserAddress, Country,
    Category, Product, ProductItem, UserReview,
    ShoppingCart, ShoppingCartItem,
    OrderStatus, ShippingMethod, PaymentMethod, ShopOrder, OrderLine,
    Promotion, PromotionCategory
};