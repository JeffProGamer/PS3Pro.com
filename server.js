// In server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const mongoUri = process.env.MONGO_URI;
const jwtSecret = process.env.JWT_SECRET || 'ps3-pro-site-secret-2025';

app.use(cors({
  origin: 'https://ps3pro-com.onrender.com',
  credentials: true
}));
app.use(express.json());

const connectWithRetry = async (retries = 15, delay = 5000) => {
  console.log(`Attempting MongoDB connection (attempt ${16 - retries})...`);
  try {
    await mongoose.connect(mongoUri, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 15000,
      connectTimeoutMS: 15000
    });
    console.log('✅ Connected to MongoDB');
  } catch (err) {
    console.error(`❌ MongoDB connection error: ${err.message}`);
    if (retries > 1) {
      console.log(`Retrying in ${delay / 1000} seconds...`);
      await new Promise(resolve => setTimeout(resolve, delay));
      return connectWithRetry(retries - 1, delay * 1.5);
    }
    console.error('❌ Failed to connect to MongoDB after retries');
    process.exit(1);
  }
};

connectWithRetry();

// ... rest of server.js (User schema, /signin, /user, /save, /load endpoints)
