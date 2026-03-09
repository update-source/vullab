const libxmljs = require("libxmljs");
const productService = require("./product.service");
//https://github.com/libxmljs/libxmljs/blob/3a44628/lib/types.ts#L106

/*
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
*/

const XMLParseVulnarebleOptions = {
  nonet: false,
  replaceEntities: true,
  validateEntities: true,
};

const xmlService = {
  async exploitingXXEUsingExternalEntitiesToRetrieveFile(data) {
    const parseData = libxmljs.parseXml(data, XMLParseVulnarebleOptions);
    const productId = parseData.get("//productId")?.text();
    const id = parseInt(productId, 10); // if productId is not a string number it will return NAN
    return {
      productId: productId,
      stock: !isNaN(id) ? await productService.getItemStock(id) : 0,
    };
  },
};

module.exports = xmlService;
