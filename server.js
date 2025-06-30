const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');

const app = express();
const port = process.env.PORT || 3000;
const secretKey = process.env.JWT_SECRET || 'ps3-pro-site-secret';
const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/ps3prosite';

// MongoDB connection with retry logic
const connectWithRetry = (retries = 5, delay = 5000) => {
  mongoose.connect(mongoUri, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('✅ Connected to MongoDB'))
    .catch(err => {
      console.error(`❌ MongoDB connection error (attempt ${6 - retries}):`, err);
      if (retries > 1) {
        setTimeout(() => connectWithRetry(retries - 1, delay), delay);
      } else {
        console.error('❌ Failed to connect to MongoDB after retries');
        process.exit(1);
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

// Rate limiting for sign-in endpoint
const signInLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // 10 requests per minute
  message: 'Too many sign-in attempts, please try again later.'
});
app.use('/signin', signInLimiter);

const validateCredentials = (username, password, provider) => {
  if (!username || !password || !provider) return false;
  if (password.length < 6) return false;
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
  res.status(200).json({ status: 'ok' });
});

app.post('/signin', async (req, res) => {
  const { username, password, provider } = req.body;
  if (!validateCredentials(username, password, provider)) {
    return res.status(400).json({ error: 'Invalid username, password, or provider' });
  }

  try {
    let user = await User.findOne({ username, provider });
    if (!user) {
      const hashedPassword = await bcrypt.hash(password, 10);
      user = await User.create({ username, password: hashedPassword, provider });
    } else {
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
    }

    const token = jwt.sign({ username, provider }, secretKey, { expiresIn: '1h' });
    res.json({ token });
  } catch (e) {
    console.error('Sign-in error:', e);
    res.status(500).json({ error: 'Server error during sign-in' });
  }
});

app.post('/verify', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  try {
    jwt.verify(token, secretKey);
    res.status(200).json({ valid: true });
  } catch (e) {
    console.error('Token verification error:', e);
    res.status(401).json({ error: 'Invalid or expired token' });
  }
});

app.get('/user', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  try {
    const decoded = jwt.verify(token, secretKey);
    const user = await User.findOne({ username: decoded.username, provider: decoded.provider });
    if (user) {
      res.json({ username: user.username, provider: user.provider });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (e) {
    console.error('User fetch error:', e);
    res.status(401).json({ error: 'Invalid or expired token' });
  }
});

app.post('/save', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  try {
    const decoded = jwt.verify(token, secretKey);
    const saveData = {
      theme: req.body.theme,
      animations: req.body.animations,
      fastMode: req.body.fastMode,
      snakeHighScore: req.body.snakeHighScore,
      platformerHighScore: req.body.platformerHighScore
    };

    await Save.findOneAndUpdate(
      { username: decoded.username },
      { data: saveData },
      { upsert: true }
    );

    res.status(200).json({ status: 'saved' });
  } catch (e) {
    console.error('Save data error:', e);
    res.status(401).json({ error: 'Invalid or expired token' });
  }
});

app.get('/load', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  try {
    const decoded = jwt.verify(token, secretKey);
    const save = await Save.findOne({ username: decoded.username });
    res.json(save?.data || {});
  } catch (e) {
    console.error('Load data error:', e);
    res.status(401).json({ error: 'Invalid or expired token' });
  }
});

// Start server
app.listen(port, () => {
  console.log(`🟢 Server running at http://localhost:${port}`);
});
