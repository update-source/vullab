require('dotenv').config({ path: require('path').resolve(__dirname, '../../.env') });
const { Sequelize, Model, DataTypes } = require('sequelize');

const sequelize = new Sequelize({
    database: process.env.DB_NAME,
    username: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    dialect: 'postgres'
});

module.exports = { sequelize, Model, DataTypes };