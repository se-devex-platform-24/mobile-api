const mongoose = require('mongoose');
require('dotenv').config();

// Database encryption configuration
const encryptionKey = process.env.DB_ENCRYPTION_KEY;
if (!encryptionKey) {
  throw new Error('Database encryption key not found in environment variables');
}

// Database connection configuration
const dbConfig = {
  url: process.env.MONGODB_URI || 'mongodb://localhost:27017/userdb',
  options: {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    ssl: process.env.NODE_ENV === 'production', // Enable SSL in production
    sslValidate: true,
    // Additional security options
    authSource: 'admin',
    retryWrites: true,
    w: 'majority' // Ensure writes are acknowledged by majority of replicas
  }
};

// Connect to MongoDB with encryption
const connectDB = async () => {
  try {
    await mongoose.connect(dbConfig.url, dbConfig.options);
    console.log('Successfully connected to the database');
    
    // Enable encryption at rest if supported by the database
    if (mongoose.connection.db.admin) {
      await mongoose.connection.db.admin().command({
        setFeatureCompatibilityVersion: '4.2',
        enableEncryption: true,
        encryptionKeyIdentifier: encryptionKey
      });
    }
  } catch (err) {
    console.error('Database connection error:', err);
    process.exit(1);
  }
};

// Export the database configuration and connection function
module.exports = {
  dbConfig,
  connectDB
};