// controllers/authController.js
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/user');
require('dotenv').config();

// Register a new user
exports.registerUser = async (req, res) => {
    console.log(req.body); 
    const { username, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, email, password: hashedPassword });
        await user.save();
  
        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        console.error('Error registering user:', err); // Log the specific error
        if (err.code === 11000) {
            // Duplicate key error for email
            return res.status(400).json({ message: 'Email is already registered.' });
        }
        res.status(500).json({ message: 'Server error' });
    }
  };
  
 


// Login a user
exports.loginUser = async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (user && await bcrypt.compare(password, user.password)) {
            const token = jwt.sign(
                { userId: user._id },
                process.env.JWT_SECRET,
                { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
            );
            res.json({ token });
        } else {
            res.status(400).json({ message: 'Invalid credentials' });
        }
    } catch (err) {
        console.error(err); // Logging for debugging
        res.status(500).json({ message: 'Server error' });
    }
};

// Optional: Get user profile
exports.getUserProfile = async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json(user);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
};

