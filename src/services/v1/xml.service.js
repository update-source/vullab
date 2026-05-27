const libxmljs = require("libxmljs");
const productService = require("./product.service");
//https://github.com/libxmljs/libxmljs/blob/3a44628/lib/types.ts#L106

/*
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
*/

const xmlService = {
  async exploitingXXEUsingExternalEntitiesToRetrieveFile(data) {
    const parseData = libxmljs.parseXml(data, {
      replaceEntities: true,
      nonet: true,
    });
    const productId = parseData.get("//productId")?.text();
    const id = parseInt(productId, 10);
    return {
      "product-id": productId,
      stock: !isNaN(id) ? await productService.getItemStock(id) : 0,
    };
  },

  //Cannot exploit ssrf because http in libxmljs is disabled by default
  //https://github.com/libxmljs/libxmljs/blob/e473f7bf/vendor/libxml2.config/libxml/xmlversion.h#L186-L188
  async exploitingXXEToPerformSSRFAttacks(data) {
    const parseData = libxmljs.parseXml(data, {
      dtdload: true,
      replaceEntities: true,
      nonet: false,
    });
    const productId = parseData.get("//productId")?.text();
    const id = parseInt(productId, 10);
    return {
      "product-id": productId,
      stock: !isNaN(id) ? await productService.getItemStock(id) : 0,
    };
  },
};

module.exports = xmlService;
