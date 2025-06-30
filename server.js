const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const path = require('path');
const morgan = require('morgan');
const fs = require('fs');

const app = express();
const port = process.env.PORT || 3000;
const secretKey = process.env.JWT_SECRET || 'ps3-pro-site-secret';
const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/ps3prosite';
const publicPath = path.join(__dirname, 'public');
const indexPath = path.join(publicPath, 'index.html');

// Check if public directory and index.html exist
if (!fs.existsSync(publicPath)) {
  console.error(`❌ Public directory not found at: ${publicPath}`);
  console.error('Please create a "public" directory and place index.html in it.');
  process.exit(1);
}
if (!fs.existsSync(indexPath)) {
  console.error(`❌ index.html not found at: ${indexPath}`);
  console.error('Please ensure index.html exists in the public directory.');
  process.exit(1);
}

// MongoDB connection with retry logic
const connectWithRetry = (retries = 5, delay = 5000) => {
  console.log(`Attempting MongoDB connection (attempt ${6 - retries})...`);
  mongoose.connect(mongoUri, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('✅ Connected to MongoDB'))
    .catch(err => {
      console.error(`❌ MongoDB connection error: ${err.message}`);
      if (retries > 1) {
        console.log(`Retrying in ${delay / 1000} seconds...`);
        setTimeout(() => connectWithRetry(retries - 1, delay), delay);
      } else {
        console.error('❌ Failed to connect to MongoDB after retries. Server will continue without MongoDB.');
      }
    });
};
connectWithRetry();

// Define MongoDB schemas
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  provider: { type: String, required: true }
});

const SaveSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  data: { type: Object, required: true }
});

const User = mongoose.model('User', UserSchema);
const Save = mongoose.model('Save', SaveSchema);

// Middleware
app.use(cors());
app.use(express.json());
app.use(morgan('dev')); // Log HTTP requests
app.use(express.static(publicPath, {
  index: false, // Disable automatic index.html serving to control via route
  setHeaders: (res, path) => {
    console.log(`Serving static file: ${path}`);
  }
})); // Serve static files from 'public'

// Rate limiting for sign-in endpoint
const signInLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // 10 requests per minute
  message: 'Too many sign-in attempts, please try again later.'
});
app.use('/signin', signInLimiter);

// Input validation
const validateCredentials = (username, password, provider) => {
  if (!username || !password || !provider) {
    console.warn('Invalid credentials: missing username, password, or provider');
    return false;
  }
  if (password.length < 6) {
    console.warn('Invalid credentials: password too short');
    return false;
  }
  if (provider === 'psn') {
    return /^[a-zA-Z0-9_-]{3,16}$/.test(username);
  } else {
    return provider === 'hotmail'
      ? /^[\w.-]+@(hotmail|outlook)\.com$/.test(username)
      : provider === 'gmail'
      ? /^[\w.-]+@gmail\.com$/.test(username)
      : false;
  }
};

// Routes
app.get('/ping', (req, res) => {
  console.log('Received /ping request');
  res.status(200).json({ status: 'ok' });
});

app.post('/signin', async (req, res, next) => {
  const { username, password, provider } = req.body;
  if (!validateCredentials(username, password, provider)) {
    return res.status(400).json({ error: 'Invalid username, password, or provider' });
  }

  try {
    let user = await User.findOne({ username, provider });
    if (!user) {
      const hashedPassword = await bcrypt.hash(password, 10);
      user = await User.create({ username, password: hashedPassword, provider });
      console.log(`Created new user: ${username} (${provider})`);
    } else {
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        console.warn(`Failed login attempt for ${username} (${provider}): invalid password`);
        return res.status(401).json({ error: 'Invalid credentials' });
      }
    }

    const token = jwt.sign({ username, provider }, secretKey, { expiresIn: '1h' });
    res.json({ token });
  } catch (e) {
    next(e);
  }
});

app.post('/verify', (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    console.warn('Verify request failed: No token provided');
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    jwt.verify(token, secretKey);
    res.status(200).json({ valid: true });
  } catch (e) {
    console.warn(`Token verification failed: ${e.message}`);
    next(e);
  }
});

app.get('/user', async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    console.warn('User request failed: No token provided');
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, secretKey);
    const user = await User.findOne({ username: decoded.username, provider: decoded.provider });
    if (user) {
      res.json({ username: user.username, provider: user.provider });
    } else {
      console.warn(`User not found: ${decoded.username} (${decoded.provider})`);
      res.status(404).json({ error: 'User not found' });
    }
  } catch (e) {
    next(e);
  }
});

app.post('/save', async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    console.warn('Save request failed: No token provided');
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, secretKey);
    const saveData = {
      theme: req.body.theme || 'default',
      animations: req.body.animations !== undefined ? req.body.animations : true,
      fastMode: req.body.fastMode || false,
      snakeHighScore: Number(req.body.snakeHighScore) || 0,
      platformerHighScore: Number(req.body.platformerHighScore) || 0
    };

    await Save.findOneAndUpdate(
      { username: decoded.username },
      { data: saveData },
      { upsert: true }
    );
    console.log(`Saved data for ${decoded.username}`);
    res.status(200).json({ status: 'saved' });
  } catch (e) {
    next(e);
  }
});

app.get('/load', async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    console.warn('Load request failed: No token provided');
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, secretKey);
    const save = await Save.findOne({ username: decoded.username });
    res.json(save?.data || {});
  } catch (e) {
    next(e);
  }
});

// Serve index.html for root route
app.get('/', (req, res) => {
  console.log(`Serving index.html from: ${indexPath}`);
  res.sendFile(indexPath, (err) => {
    if (err) {
      console.error(`❌ Failed to serve index.html: ${err.message}`);
      res.status(404).json({ error: 'index.html not found. Please ensure it exists in the public directory.' });
    }
  });
});

// Catch-all route for single-page application
app.get('*', (req, res) => {
  console.log(`Serving index.html for catch-all route: ${req.path}`);
  res.sendFile(indexPath, (err) => {
    if (err) {
      console.error(`❌ Failed to serve index.html: ${err.message}`);
      res.status(404).json({ error: 'index.html not found. Please ensure it exists in the public directory.' });
    }
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(`❌ Server error: ${err.message}`, err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(port, () => {
  console.log(`🟢 Server running at http://localhost:${port}`);
}).on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`❌ Port ${port} is in use. Please free the port or use a different one.`);
  } else {
    console.error(`❌ Server startup error: ${err.message}`);
  }
  process.exit(1);
});
