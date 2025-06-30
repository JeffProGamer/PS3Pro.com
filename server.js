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

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: String,
  provider: String,
  theme: String,
  fastMode: Boolean,
  snakeHighScore: Number,
  platformerHighScore: Number
});

const User = mongoose.model('User', userSchema);

app.get('/ping', (req, res) => {
  res.json({ status: 'ok' });
});

app.post('/signin', async (req, res) => {
  try {
    console.log('Received /signin request:', req.body);
    const { username, password, provider } = req.body;
    if (!username || !password || !provider) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    let user = await User.findOne({ username });
    if (!user) {
      user = new User({ username, password, provider, theme: 'default', fastMode: false, snakeHighScore: 0, platformerHighScore: 0 });
      await user.save();
      console.log(`Created new user: ${username}`);
    } else if (user.password !== password || user.provider !== provider) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ username }, jwtSecret, { expiresIn: '1h' });
    console.log(`Sign-in successful for ${username}`);
    res.json({ token });
  } catch (e) {
    console.error('Sign-in error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/user', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });
    const decoded = jwt.verify(token, jwtSecret);
    const user = await User.findOne({ username: decoded.username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ username: user.username, provider: user.provider });
  } catch (e) {
    console.error('User fetch error:', e.message);
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.post('/save', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });
    const decoded = jwt.verify(token, jwtSecret);
    const user = await User.findOne({ username: decoded.username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.theme = req.body.theme || user.theme;
    user.fastMode = req.body.fastMode !== undefined ? req.body.fastMode : user.fastMode;
    user.snakeHighScore = req.body.snakeHighScore || user.snakeHighScore;
    user.platformerHighScore = req.body.platformerHighScore || user.platformerHighScore;
    await user.save();
    res.json({ status: 'saved' });
  } catch (e) {
    console.error('Save error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/load', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });
    const decoded = jwt.verify(token, jwtSecret);
    const user = await User.findOne({ username: decoded.username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({
      theme: user.theme,
      fastMode: user.fastMode,
      snakeHighScore: user.snakeHighScore,
      platformerHighScore: user.platformerHighScore
    });
  } catch (e) {
    console.error('Load error:', e.message);
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// ... rest of server.js (User schema, /signin, /user, /save, /load endpoints)
