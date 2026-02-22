// Dữ liệu tham chiếu (Reference Data) - BẮT BUỘC cho Production
// Các ID nên được cố định nếu cần reference cứng trong code

module.exports = {
  orderStatuses: [
    {
      code: "pending",
      displayName: "Chờ xử lý",
      color: "#FFA500",
      displayOrder: 1,
    },
    {
      code: "processing",
      displayName: "Đang chuẩn bị hàng",
      color: "#3498db",
      displayOrder: 2,
    },
    {
      code: "shipped",
      displayName: "Đang giao hàng",
      color: "#9b59b6",
      displayOrder: 3,
    },
    {
      code: "delivered",
      displayName: "Giao thành công",
      color: "#2ecc71",
      displayOrder: 4,
    },
    {
      code: "cancelled",
      displayName: "Đã hủy",
      color: "#e74c3c",
      displayOrder: 5,
    },
  ],

  paymentMethods: [
    {
      code: "cod",
      methodName: "Thanh toán khi nhận hàng (COD)",
      isActive: true,
    },
    { code: "banking", methodName: "Chuyển khoản ngân hàng", isActive: true },
    { code: "credit_card", methodName: "Thẻ tín dụng", isActive: true },
  ],

  shippingMethods: [
    {
      code: "standard",
      name: "Giao hàng tiêu chuẩn",
      price: 30000,
      estimatedDaysMin: 3,
      estimatedDaysMax: 5,
    },
    {
      code: "express",
      name: "Giao hàng hỏa tốc",
      price: 100000,
      estimatedDaysMin: 0,
      estimatedDaysMax: 1,
    },
  ],

  countries: [
    { countryName: "Vietnam", countryCode: "VN" },
    { countryName: "United States", countryCode: "US" },
  ],
};
