const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fs = require('fs-extra');
const path = require('path');

const app = express();
const port = 3000;
const secretKey = 'ps3-pro-site-secret';

const usersFile = path.join(__dirname, 'data', 'users.json');
const savedDataFile = path.join(__dirname, 'data', 'savedData.json');

app.use(cors({ origin: 'http://localhost' }));
app.use(express.json());

const loadUsers = () => fs.readJson(usersFile).catch(() => []);
const saveUsers = (users) => fs.writeJson(usersFile, users, { spaces: 2 });

const loadSavedData = () => fs.readJson(savedDataFile).catch(() => ({}));
const saveSavedData = (data) => fs.writeJson(savedDataFile, data, { spaces: 2 });

const validateCredentials = (username, provider) => {
  if (!username || !provider) return false;
  if (provider === 'psn') {
    return /^[a-zA-Z0-9_-]{3,16}$/.test(username);
  } else {
    return provider === 'hotmail' ? /^[\w-\.]+@(hotmail|outlook)\.com$/.test(username) :
           provider === 'gmail' ? /^[\w-\.]+@gmail\.com$/.test(username) : false;
  }
};

app.post('/signin', async (req, res) => {
  const { username, password, provider } = req.body;
  if (!username || !password || !provider) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  if (!validateCredentials(username, provider)) {
    return res.status(400).json({ error: 'Invalid email or PSN ID' });
  }

  let users = await loadUsers();
  let user = users.find(u => u.username === username && u.password === password && u.provider === provider);

  if (!user) {
    // Register new user
    user = { username, password, provider };
    users.push(user);
    await saveUsers(users);
  }

  const token = jwt.sign({ username, provider }, secretKey, { expiresIn: '1h' });
  res.json({ token });
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

app.get('/user', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, secretKey);
    const users = await loadUsers();
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

app.post('/save', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, secretKey);
    const { theme, animations, fastMode, snakeHighScore, platformerHighScore } = req.body;
    const savedData = await loadSavedData();
    savedData[decoded.username] = { theme, animations, fastMode, snakeHighScore, platformerHighScore };
    await saveSavedData(savedData);
    res.status(200).json({ status: 'saved' });
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.get('/load', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, secretKey);
    const savedData = await loadSavedData();
    const data = savedData[decoded.username] || {};
    res.json(data);
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
