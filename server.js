const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const mongoose = require('mongoose');

const app = express();
const port = process.env.PORT || 3000;
const secretKey = 'ps3-pro-site-secret'; // 🔐 You can move this to an env var too

// ✅ Connect to MongoDB (non-SRV URI for Render)
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// ✅ Define MongoDB schemas
const UserSchema = new mongoose.Schema({
  username: String,
  password: String,
  provider: String
});

const SaveSchema = new mongoose.Schema({
  username: String,
  data: Object
});

const User = mongoose.model('User', UserSchema);
const Save = mongoose.model('Save', SaveSchema);

// ✅ Middleware
app.use(cors());
app.use(express.json());

const validateCredentials = (username, provider) => {
  if (!username || !provider) return false;
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

// ✅ Routes
app.get('/ping', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

app.post('/signin', async (req, res) => {
  const { username, password, provider } = req.body;
  if (!username || !password || !provider) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  if (!validateCredentials(username, provider)) {
    return res.status(400).json({ error: 'Invalid email or PSN ID' });
  }

  let user = await User.findOne({ username, provider });
  if (!user) {
    user = await User.create({ username, password, provider });
  } else if (user.password !== password) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ username, provider }, secretKey, { expiresIn: '1h' });
  res.json({ token });
});

app.post('/verify', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });

  try {
    jwt.verify(token, secretKey);
    res.status(200).json({ valid: true });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.get('/user', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });

  try {
    const decoded = jwt.verify(token, secretKey);
    const user = await User.findOne({ username: decoded.username, provider: decoded.provider });
    if (user) {
      res.json({ username: user.username, provider: user.provider });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.post('/save', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });

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
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.get('/load', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });

  try {
    const decoded = jwt.verify(token, secretKey);
    const save = await Save.findOne({ username: decoded.username });
    res.json(save?.data || {});
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// ✅ Start server
app.listen(port, () => {
  console.log(`🟢 Server running at http://localhost:${port}`);
});
