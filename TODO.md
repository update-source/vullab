# Project TODOs

## Future Enhancements (Post-MVP)

### 1. Payment Processing (Advanced)
- [ ] **Create `Transaction` or `PaymentLog` model**: 
  - Purpose: To store detailed payment gateway responses.
  - Fields needed: Transaction ID (from Stripe/PayPal), Payment Status (Success/Fail/Pending), Failure Reason, Refund Status, JSON payload of the raw response.
  - *Current Status*: Only tracking basic payment method and status in `ShopOrder`.

### 2. Inventory Management (Advanced)
- [ ] **Create `StockMovementLog` model**:
  - Purpose: To track the history of stock changes (Audit Trail).
  - Fields needed: ProductItemId, ChangeAmount (+/-), Reason (Order, Restock, Damage), Actor (Admin User ID), Timestamp.
- [ ] **Warehouse Support (Optional)**:
  - Purpose: Support multiple inventory locations.
  - *Current Status*: Only tracking simple `quantityInStock` in `ProductItem`.
