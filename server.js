```javascript
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
const port = process.env.PORT || 10000;
const host = '0.0.0.0';
const secretKey = process.env.JWT_SECRET || 'ps3-pro-site-secret';
const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/ps3prosite';
const publicPath = path.join(__dirname, 'public');
const indexPath = path.join(publicPath, 'index.html');
const responseCache = new Map();

// Check public directory and index.html
if (!fs.existsSync(publicPath) || !fs.existsSync(indexPath)) {
  console.error(`❌ Public directory or index.html not found at: ${publicPath}`);
  process.exit(1);
}

// MongoDB connection with enhanced retry logic
const connectWithRetry = async (retries = 10, delay = 5000) => {
  console.log(`Attempting MongoDB connection (attempt ${11 - retries})...`);
  try {
    await mongoose.connect(mongoUri, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 10000, // Increased timeout
      connectTimeoutMS: 10000
    });
    console.log('✅ Connected to MongoDB');
  } catch (err) {
    console.error(`❌ MongoDB connection error: ${err.message}`);
    if (retries > 1) {
      console.log(`Retrying in ${delay / 1000} seconds...`);
      await new Promise(resolve => setTimeout(resolve, delay));
      return connectWithRetry(retries - 1, delay * 1.2);
    }
    console.error('❌ Failed to connect to MongoDB after retries');
  }
};
connectWithRetry();

// MongoDB schemas
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
app.use(cors({
  origin: 'https://ps3pro-com.onrender.com',
  credentials: true
}));
app.use(express.json());
app.use(morgan('dev', {
  stream: { write: msg => console.log(msg.trim()) }
}));
app.use(express.static(publicPath, {
  index: false,
  setHeaders: (res, path) => {
    console.log(`Serving static file: ${path}`);
  }
}));

// Rate limiting (relaxed for testing)
const signInLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20, // Increased limit
  message: 'Too many sign-in attempts, please try again later.'
});
app.use('/signin', signInLimiter);

// Input validation
const validateCredentials = (username, password, provider) => {
  if (!username || !password || !provider) {
    console.warn(`Invalid credentials: username=${username}, provider=${provider}`);
    return { valid: false, error: 'Missing username, password, or provider' };
  }
  if (password.length < 6) {
    console.warn('Invalid credentials: password too short');
    return { valid: false, error: 'Password must be at least 6 characters' };
  }
  if (provider === 'psn') {
    return { valid: /^[a-zA-Z0-9_-]{3,16}$/.test(username), error: 'Invalid PSN username' };
  } else if (provider === 'gmail') {
    return { valid: /^[\w.-]+@gmail\.com$/.test(username), error: 'Invalid Gmail address' };
  } else if (provider === 'hotmail') {
    return { valid: /^[\w.-]+@(hotmail|outlook)\.com$/.test(username), error: 'Invalid Hotmail/Outlook address' };
  }
  return { valid: false, error: 'Invalid provider' };
};

// Routes
app.get('/ping', (req, res) => {
  console.log('Received /ping request');
  res.status(200).json({ status: 'ok' });
});

app.post('/signin', async (req, res, next) => {
  console.log(`Received /signin request: ${JSON.stringify(req.body)}`);
  const { username, password, provider } = req.body;
  const validation = validateCredentials(username, password, provider);
  if (!validation.valid) {
    console.warn(`Sign-in failed: ${validation.error}`);
    return res.status(400).json({ error: validation.error });
  }
  try {
    let user = await User.findOne({ username, provider });
    if (!user) {
      console.log(`Creating new user: ${username} (${provider})`);
      const hashedPassword = await bcrypt.hash(password, 10);
      user = await User.create({ username, password: hashedPassword, provider });
    } else {
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        console.warn(`Sign-in failed for ${username} (${provider}): invalid password`);
        return res.status(401).json({ error: 'Invalid credentials' });
      }
    }
    const token = jwt.sign({ username, provider }, secretKey, { expiresIn: '1h' });
    console.log(`Sign-in successful for ${username} (${provider})`);
    res.json({ token });
  } catch (e) {
    console.error(`Sign-in error: ${e.message}`);
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
    console.log('Token verified successfully');
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
    const cacheKey = `user:${decoded.username}:${decoded.provider}`;
    if (responseCache.has(cacheKey)) {
      console.log(`Serving cached user data: ${cacheKey}`);
      return res.json(responseCache.get(cacheKey));
    }
    const user = await User.findOne({ username: decoded.username, provider: decoded.provider });
    if (user) {
      const userData = { username: user.username, provider: user.provider };
      responseCache.set(cacheKey, userData);
      console.log(`Fetched user data: ${user.username} (${user.provider})`);
      res.json(userData);
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
    const cacheKey = `save:${decoded.username}`;
    responseCache.set(cacheKey, saveData);
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
    const cacheKey = `save:${decoded.username}`;
    if (responseCache.has(cacheKey)) {
      console.log(`Serving cached save data: ${cacheKey}`);
      return res.json(responseCache.get(cacheKey));
    }
    const save = await Save.findOne({ username: decoded.username });
    const data = save?.data || {};
    responseCache.set(cacheKey, data);
    console.log(`Fetched save data for ${decoded.username}`);
    res.json(data);
  } catch (e) {
    next(e);
  }
});

app.get('/', (req, res) => {
  console.log(`Serving index.html from: ${indexPath}`);
  res.sendFile(indexPath, err => {
    if (err) {
      console.error(`❌ Failed to serve index.html: ${err.message}`);
      res.status(404).json({ error: 'index.html not found' });
    }
  });
});

app.get('*', (req, res) => {
  console.log(`Serving index.html for catch-all route: ${req.path}`);
  res.sendFile(indexPath, err => {
    if (err) {
      console.error(`❌ Failed to serve index.html: ${err.message}`);
      res.status(404).json({ error: 'index.html not found' });
    }
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(`❌ Server error: ${err.message}`, err.stack);
  res.status(500).json({ error: 'Internal server error', details: err.message });
});

// Start server
app.listen(port, host, () => {
  console.log(`🟢 Server running at http://${host}:${port}`);
}).on('error', err => {
  console.error(`❌ Server startup error: ${err.message}`);
  process.exit(1);
});
```
