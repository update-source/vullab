// Dữ liệu mẫu (Dummy Data) - CHỈ DÙNG CHO MÔI TRƯỜNG DEV
// Giúp dev có dữ liệu test ngay lập tức

module.exports = {
    categories: [
        {
            categoryName: 'Điện tử',
            slug: 'dien-tu',
            children: [
                { categoryName: 'Điện thoại', slug: 'dien-thoai' },
                { categoryName: 'Laptop', slug: 'laptop' }
            ]
        },
        {
            categoryName: 'Thời trang',
            slug: 'thoi-trang'
        }
    ],

    products: [
        {
            name: 'iPhone 15 Pro Max',
            slug: 'iphone-15-pro-max', // Assuming you might want slugs later, keeping logical structure
            sku: 'IP15-PROMAX',
            description: 'Điện thoại xịn nhất 2024',
            variants: [
                { sku: 'IP15-PM-256-BLK', price: 29990000, quantityInStock: 50 },
                { sku: 'IP15-PM-512-NAT', price: 35990000, quantityInStock: 20 }
            ]
        },
        {
            name: 'MacBook Air M2',
            sku: 'MAC-AIR-M2',
            description: 'Siêu mỏng siêu nhẹ',
            variants: [
                { sku: 'MAC-M2-8-256', price: 24500000, quantityInStock: 100 }
            ]
        }
    ]
};
