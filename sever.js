const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const app = express();
const port = 3000;
const secretKey = 'ps3-pro-site-secret'; // Replace with secure key in production

app.use(cors({ origin: 'http://localhost' }));
app.use(express.json());

// Mock user database
const users = [
  { username: 'testuser@hotmail.com', password: 'password123', provider: 'hotmail' },
  { username: 'testuser@gmail.com', password: 'password123', provider: 'gmail' },
  { username: 'test_user123', password: 'password123', provider: 'psn' }
];

// Mock saved data
const savedData = {};

const validateCredentials = (username, provider) => {
  if (!username || !provider) return false;
  if (provider === 'psn') {
    return /^[a-zA-Z0-9_-]{3,16}$/.test(username);
  } else {
    return provider === 'hotmail' ? /^[\w-\.]+@(hotmail|outlook)\.com$/.test(username) :
           provider === 'gmail' ? /^[\w-\.]+@gmail\.com$/.test(username) : false;
  }
};

app.get('/ping', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

app.post('/signin', (req, res) => {
  const { username, password, provider } = req.body;
  if (!username || !password || !provider) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  if (!validateCredentials(username, provider)) {
    return res.status(400).json({ error: 'Invalid email or PSN ID' });
  }
  const user = users.find(u => u.username === username && u.password === password && u.provider === provider);
  if (user) {
    const token = jwt.sign({ username, provider }, secretKey, { expiresIn: '1h' });
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

app.post('/verify', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    jwt.verify(token, secretKey);
    res.status(200).json({ valid: true });
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.get('/user', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, secretKey);
    const user = users.find(u => u.username === decoded.username && u.provider === decoded.provider);
    if (user) {
      res.json({ username: user.username, provider: user.provider });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.post('/save', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, secretKey);
    const { theme, animations, fastMode, snakeHighScore, platformerHighScore } = req.body;
    savedData[decoded.username] = { theme, animations, fastMode, snakeHighScore, platformerHighScore };
    res.status(200).json({ status: 'saved' });
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.get('/load', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, secretKey);
    const data = savedData[decoded.username] || {};
    res.json(data);
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
