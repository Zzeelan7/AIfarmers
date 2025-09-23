// server.js
require('dotenv').config();
const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const PORT = process.env.PORT || 3000;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

// Serve static files (CSS, JS, HTML)
app.use(express.static(path.join(__dirname, "public")));


// Middlewares
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error('MongoDB connection error:', err));

// Mongoose User model
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, required: true },
  passwordHash: String,
  googleId: String,
  farmType: String,
  location: String, // e.g. "Bangalore"
  locationLat: Number,
  locationLon: Number,
  createdAt: { type: Date, default: Date.now }
});


const User = mongoose.model('User', userSchema);

// Helpers
function createToken(user) {
  return jwt.sign({ id: user._id, name: user.name, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
}

// Routes
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });

    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ error: 'User already exists' });

    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, passwordHash: hash });
    const token = createToken(user);
    res.json({ token, user: { name: user.name, email: user.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

    const user = await User.findOne({ email });
    if (!user || !user.passwordHash) return res.status(400).json({ error: 'Invalid credentials or use Google Sign-in' });

    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) return res.status(400).json({ error: 'Invalid credentials' });

    const token = createToken(user);
    res.json({ token, user: { name: user.name, email: user.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/google', async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: 'Missing credential' });

    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID
    });
    const payload = ticket.getPayload();
    const { sub: googleId, email, name } = payload;

    let user = await User.findOne({ email });
    if (!user) {
      user = await User.create({ name, email, googleId });
    } else if (!user.googleId) {
      user.googleId = googleId;
      await user.save();
    }

    const token = createToken(user);
    res.json({ token, user: { name: user.name, email: user.email } });
  } catch (err) {
    console.error('Google auth error', err);
    res.status(401).json({ error: 'Invalid Google token' });
  }
});

// Simple authenticated endpoint: GET /api/me
app.get('/api/me', async (req, res) => {
  try {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'No token' });
    const token = auth.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select('-passwordHash');
    if (!user) return res.status(401).json({ error: 'Invalid token' });
    res.json({ user });
  } catch (err) {
    console.error(err);
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.put('/api/updateProfile', async (req, res) => {
  try {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'No token' });
    const token = auth.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const { name, farmType, location } = req.body;
    const user = await User.findByIdAndUpdate(
      decoded.id,
      { name, farmType, location },
      { new: true }
    ).select('-passwordHash');

    res.json({ user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Update failed' });
  }
});

const axios = require("axios"); // install if not already: npm install axios

// Weather API (Open-Meteo)
app.get("/api/weather", async (req, res) => {
  try {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: "No token" });
    const token = auth.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await User.findById(decoded.id);
    if (!user) return res.status(404).json({ error: "User not found" });

    let { lat, lon } = req.query; // optional query params

    // fallback to user profile location if available
    if (!lat || !lon) {
      if (!user.locationLat || !user.locationLon) {
        return res.status(400).json({ error: "No coordinates available" });
      }
      lat = user.locationLat;
      lon = user.locationLon;
    }

    const url = `https://api.open-meteo.com/v1/forecast?latitude=${lat}&longitude=${lon}&current_weather=true&hourly=temperature_2m,relative_humidity_2m,precipitation`;


    const response = await axios.get(url);
    res.json({ weather: response.data });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Weather fetch failed" });
  }
});

// Route to get mandi price from CSV

// const fs = require("fs");
// const csv = require("csv-parser");



// app.get("/api/market", (req, res) => {
//   const { state, mandi, crop } = req.query;

//   if (!state || !mandi || !crop) {
//     return res.status(400).json({ error: "State, Mandi, and Crop are required" });
//   }

//   const filePath = path.join(__dirname, "data", "market.csv");
//   const results = [];

//   fs.createReadStream(filePath)
//     .pipe(csv())
//     .on("data", (row) => {
//       if (
//         row.state_name?.toLowerCase() === state.toLowerCase() &&
//         row.district_name?.toLowerCase() === mandi.toLowerCase() &&
//         row.commodity?.toLowerCase() === crop.toLowerCase()
//       ) {
//         results.push(row);
//       }
//     })
//     .on("end", () => {
//       if (results.length === 0) {
//         return res.status(404).json({ error: "No records found" });
//       }

//       results.sort((a, b) => new Date(b.arrival_date) - new Date(a.arrival_date));
//       const latest = results[0];

//       res.json({
//         state: latest.state_name,
//         mandi: latest.district_name,
//         crop: latest.commodity,
//         variety: latest.variety,
//         grade: latest.grade,
//         min_price: latest.min_price,
//         max_price: latest.max_price,
//         modal_price: latest.modal_price,
//         arrival_date: latest.arrival_date
//       });
//     })
//     .on("error", (err) => {
//       console.error("CSV Read Error:", err.message);
//       res.status(500).json({ error: "Failed to read dataset" });
//     });
// });




// Start
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
