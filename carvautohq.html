require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(bodyParser.json());

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });

// User schema
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'user' }
});
const User = mongoose.model('User', userSchema);

// Vehicle schema
const vehicleSchema = new mongoose.Schema({
    vin: String,
    make: String,
    model: String,
    trim: String,
    mileage: Number,
    price: Number,
    sold: { type: Boolean, default: false },
    offers: [{ userId: String, amount: Number }],
    userGroups: [String],
});
const Vehicle = mongoose.model('Vehicle', vehicleSchema);

// Auth middleware
const auth = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.sendStatus(403);
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Register admin user
app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    if (email !== 'carvautosolutions@gmail.com') return res.status(403).send('Only admin can register users.');
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ email, password: hashedPassword, role: 'admin' });
    await newUser.save();
    res.send('User registered');
});

// Login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).send('Invalid credentials');
    }
    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET);
    res.json({ token });
});

// Add vehicle (admin only)
app.post('/vehicles', auth, async (req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    const { vin, mileage, price, userGroups } = req.body;
    const vinData = await axios.get(`https://api.vindecoder.eu/lookup/${vin}`); // Replace with a valid VIN API
    const { make, model, trim } = vinData.data; // Adjust based on the API response
    const newVehicle = new Vehicle({ vin, make, model, trim, mileage, price, userGroups });
    await newVehicle.save();
    res.send('Vehicle added');
});

// Make an offer
app.post('/vehicles/:id/offer', auth, async (req, res) => {
    const { id } = req.params;
    const { amount } = req.body;
    const vehicle = await Vehicle.findById(id);
    vehicle.offers.push({ userId: req.user.id, amount });
    await vehicle.save();
    // Notify admin via email (implementation depends on your choice of email service)
    res.send('Offer made');
});

// Mark vehicle as sold
app.post('/vehicles/:id/sold', auth, async (req, res) => {
    const { id } = req.params;
    const vehicle = await Vehicle.findById(id);
    vehicle.sold = true;
    await vehicle.save();
    // Notify admin via email
    res.send('Vehicle marked as sold');
});

// Dashboard for user
app.get('/dashboard', auth, async (req, res) => {
    const vehicles = await Vehicle.find({ 'offers.userId': req.user.id });
    res.json(vehicles);
});

// VIN decoding
app.get('/decode-vin/:vin', async (req, res) => {
    const vin = req.params.vin;
    const vinData = await axios.get(`https://api.vindecoder.eu/lookup/${vin}`); // Replace with a valid VIN API
    res.json(vinData.data);
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
