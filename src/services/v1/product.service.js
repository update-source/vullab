const { ProductItem } = require("../../models");

const productService = {
  async getItemStock(itemId) {
    const item = await ProductItem.findByPk(itemId, {
      attributes: ["quantityInStock"],
      raw: true,
    });
    return item ? item.quantityInStock : 0;
  },
};

module.exports = productService;
