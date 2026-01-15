const mongoose = require('mongoose');
const logger = require('../utils/logger');

const MONGO_URI = process.env.MONGO_URI ;

async function connectDB() {
  mongoose.set('strictQuery', true);
  await mongoose.connect(MONGO_URI, {
    autoIndex: true
  });
  logger.info('Connected to MongoDB');
}

module.exports = { connectDB };