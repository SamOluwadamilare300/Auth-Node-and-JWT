    // FOR DEVELOPMENT

const express = require('express');
const app = express();
const port = 9000;
const Datastore = require('nedb-promises');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { authenticator } = require('otplib');
const qrcode = require('qrcode');
const config = require('./config');
const crypto = require('crypto');
const NodeCache = require('node-cache');

// Middleware to parse JSON data
app.use(express.json());

const myCache = new NodeCache();

// Create a new database
const users = Datastore.create('Users.db');
const userRefreshTokens = Datastore.create('UserRefreshTokens.db');
const userInvalidTokens = Datastore.create('UserInvalidTokens.db');

// Home route
app.get('/', (req, res) => {
  res.send('REST API Authentication and Authorization');
});

// Register a new User route
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password) {
      return res.status(422).json({ message: "Please fill in all fields (name, email, password) correctly!" });
    }

    if (await users.findOne({ email })) {
      return res.status(409).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await users.insert({ name, email, password: hashedPassword, role: role ?? 'member', "2faEnabled": false, "2faSecret": null });

    return res.status(201).json({ message: 'User created successfully', id: newUser._id });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

// Login a user route
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(422).json({ message: "Please fill in all fields (email, password) correctly!" });
    }

    const user = await users.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "User does not exist!" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid password!" });
    }

    if (user['2faEnabled']) {
      const tempToken = crypto.randomUUID();
      myCache.set(config.cacheTemporaryTokenPrefix + tempToken, user._id, config.cacheTemporaryTokenExpireInSeconds);
      return res.status(200).json({ tempToken, expiresInSeconds: config.cacheTemporaryTokenExpireInSeconds });
    } else {
      const jwtToken = jwt.sign(
        { userId: user._id },
        config.accessTokenSecret,
        { expiresIn: config.accessTokenExpiresIn, subject: "accessAPI" }
      );
      const refreshToken = jwt.sign(
        { userId: user._id },
        config.refreshTokenSecret,
        { subject: "refreshToken", expiresIn: config.refreshTokenExpiresIn }
      );
      await userRefreshTokens.insert({ userId: user._id, refreshToken });

      return res.status(200).json({ id: user._id, token: jwtToken, name: user.name, email: user.email, refreshToken });
    }
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

// 2fa Enable Login User
app.post('/api/auth/login/2fa', async (req, res) => {
  try {
    const { tempToken, totp } = req.body;

    if (!tempToken || !totp) {
      return res.status(422).json({ message: 'Please fill all fields (tempToken and totp)' });
    }

    const userId = myCache.get(config.cacheTemporaryTokenPrefix + tempToken);
    if (!userId) {
      return res.status(401).json({ message: 'The provided temporary token is incorrect or expired' });
    }

    const user = await users.findOne({ _id: userId });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (!user['2faSecret']) {
      return res.status(400).json({ message: '2FA is not set up for this user' });
    }

    const verified = authenticator.check(totp, user['2faSecret']);
    if (!verified) {
      return res.status(401).json({ message: 'The provided TOTP is incorrect or expired' });
    }

    const jwtToken = jwt.sign(
      { userId: user._id },
      config.accessTokenSecret,
      { expiresIn: config.accessTokenExpiresIn, subject: "accessAPI" }
    );
    const refreshToken = jwt.sign(
      { userId: user._id },
      config.refreshTokenSecret,
      { subject: "refreshToken", expiresIn: config.refreshTokenExpiresIn }
    );
    await userRefreshTokens.insert({ userId: user._id, refreshToken });

    return res.status(200).json({ id: user._id, token: jwtToken, name: user.name, email: user.email, refreshToken });

  } catch (error) {
    if (error.message.includes('Received null')) {
      return res.status(500).json({ message: 'Error with 2FA Secret: ' + error.message });
    }
    return res.status(500).json({ message: error.message });
  }
});

// Refresh Token Route
app.post('/api/auth/refresh-token', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(401).json({ message: "Refresh Token Not Found!" });
    }

    const decodedRefreshedToken = jwt.verify(refreshToken, config.refreshTokenSecret);
    const userRefreshToken = await userRefreshTokens.findOne({ userId: decodedRefreshedToken.userId, refreshToken });

    if (!userRefreshToken) {
      return res.status(401).json({ message: "Refresh token not found!" });
    }

    await userRefreshTokens.remove({ _id: userRefreshToken._id });
    await userRefreshTokens.persistence.compactDatafile();

    const jwtToken = jwt.sign(
      { userId: decodedRefreshedToken.userId },
      config.accessTokenSecret,
      { expiresIn: config.accessTokenExpiresIn, subject: "accessAPI" }
    );
    const newRefreshToken = jwt.sign(
      { userId: decodedRefreshedToken.userId },
      config.refreshTokenSecret,
      { subject: "refreshToken", expiresIn: config.refreshTokenExpiresIn }
    );
    await userRefreshTokens.insert({ userId: decodedRefreshedToken.userId, refreshToken: newRefreshToken });

    return res.status(200).json({ jwtToken, refreshToken: newRefreshToken });
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError || error instanceof jwt.JsonWebTokenError) {
      return res.status(401).json({ message: "Invalid or Expired Refresh Token!" });
    }
    return res.status(500).json({ message: error.message });
  }
});

// 2FA Generator Route
app.get('/api/auth/2fa/generate', ensureAuthenticated, async (req, res) => {
  try {
    const user = await users.findOne({ _id: req.user._id });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const secret = authenticator.generateSecret();
    const url = authenticator.keyuri(user.email, 'Fold, Inc.', secret);

    await users.update({ _id: req.user._id }, { $set: { "2faSecret": secret } });
    await users.persistence.compactDatafile();

    const qrCode = await qrcode.toBuffer(url, { type: 'image/png', margin: 1 });
    res.setHeader('Content-Disposition', 'attachment; filename=qrcode.png');
    return res.status(200).type('image/png').send(qrCode);
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

// 2FA Enable Route
app.post('/api/auth/2fa/validate', ensureAuthenticated, async (req, res) => {
  try {
    const { totp } = req.body;
    if (!totp) {
      return res.status(422).json({ message: "Please fill in the TOTP field correctly!" });
    }

    const user = await users.findOne({ _id: req.user._id });
    if (!user || !user['2faSecret']) {
      return res.status(404).json({ message: "User not found or 2FA not set up!" });
    }

    const verified = authenticator.check(totp, user['2faSecret']);

    if (!verified) {
      return res.status(400).json({ message: "Invalid TOTP code!" });
    }

    await users.update({ _id: req.user._id }, { $set: { "2faEnabled": true } });
    await users.persistence.compactDatafile();

    return res.status(200).json({ message: "TOTP enabled successfully!" });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

// Logout Route
app.get('/api/auth/logout', ensureAuthenticated, async (req, res) => {
  try {
    await userRefreshTokens.remove({ userId: req.user._id });
    await userRefreshTokens.persistence.compactDatafile();

    await userInvalidTokens.insert({
      accessToken: req.accessToken.value,
      userId: req.user._id,
      exp: req.accessToken.exp
    });

    return res.status(204).send();
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

// Get Current User route
app.get('/api/users/current', ensureAuthenticated, async (req, res) => {
  try {
    const user = await users.findOne({ _id: req.user._id });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    return res.status(200).json({ id: user._id, name: user.name, email: user.email });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

// Admin User Route (Protected Route)
app.get('/api/admin', ensureAuthenticated, authorized(['admin']), (req, res) => {
  return res.status(200).json({ message: 'Only Admin can access this route!' });
});

// Admin and Moderator User Route (Protected Route)
app.get('/api/moderator', ensureAuthenticated, authorized(['admin', 'moderator']), (req, res) => {
  return res.status(200).json({ message: 'Only Admin and Moderator can access this route!' });
});

async function ensureAuthenticated(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ message: "Access token is required" });
  }

  const token = authHeader.split(' ')[1];
  console.log('Token:', token); // Debugging line

  if (!token) {
    return res.status(401).json({ message: "Token is missing from the authorization header" });
  }

  if (await userInvalidTokens.findOne({ accessToken: token })) {
    return res.status(401).json({ message: 'Invalid token!', code: 'invalid_token' });
  }

  try {
    const decodedAccessToken = jwt.verify(token, config.accessTokenSecret);
    req.accessToken = { value: token, exp: decodedAccessToken.exp };
    req.user = { _id: decodedAccessToken.userId };

    next();
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      return res.status(401).json({ message: 'Token expired!', code: 'token_expired' });
    } else if (error instanceof jwt.JsonWebTokenError) {
      return res.status(401).json({ message: 'Invalid token!', code: 'invalid_token' });
    } else {
      return res.status(500).json({ message: error.message });
    }
  }
}

function authorized(roles = []) {
  return async (req, res, next) => {
    const user = await users.findOne({ _id: req.user._id });
    if (!user || !roles.includes(user.role)) {
      return res.status(403).json({ message: 'You are not authorized to access this route' });
    }
    next();
  };
}

// Start the server on port 9000
app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});