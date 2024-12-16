const express = require('express');
const cors = require('cors');
const requestLogger = require('./middleware/requestLogger');
const authRoutes = require('./routes/authRoutes');
const adminRoutes = require('./routes/adminRoutes');

require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Request logging middleware
app.use(requestLogger);

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);

// Error handling
app.use((err, req, res, next) => {
    console.error('\n=== Auth Service Error Log ===');
    console.error('Time:', new Date().toISOString());
    console.error('Error:', err);
    console.error('Stack:', err.stack);
    console.error('========================\n');
    res.status(500).json({ message: 'Something went wrong!' });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Auth Service running on port ${PORT}`);
});
