// config/index.js
require('dotenv').config();

module.exports = {
  APP_TOKEN: process.env.SUMSUB_APP_TOKEN,
  SECRET_KEY: process.env.SUMSUB_SECRET_KEY
};
