/**
 * Services Index
 * Central export point for all service versions
 */

const v1 = require('./v1');
const v2 = require('./v2');

module.exports = {
    v1,
    v2
};
