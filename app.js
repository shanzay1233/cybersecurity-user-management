const express = require('express');
const validator = require('validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const winston = require('winston');

const app = express();

// Week 3: Setup Basic Security Logging using Winston
const logger = winston.createLogger({
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'security.log' })
    ]
});

logger.info('Application started successfully in secure mode.');

// Secure Data Transmission using Helmet
app.use(helmet());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Mock Database
const usersDB = [];
const SECRET_KEY = "my_super_secret_cyber_key";

// Home Route
app.get('/', (req, res) => {
    res.send(`
        <h1>Week 3: Advanced Secure Application</h1>
        <h3>1. Signup (With Validation & Hashing)</h3>
        <form action="/signup" method="POST">
            <input type="text" name="email" placeholder="Enter Email" required><br><br>
            <input type="password" name="password" placeholder="Enter Password" required><br><br>
            <input type="submit" value="Register User">
        </form>
        <hr>
        <h3>2. Login (Generates JWT & Logs Activity)</h3>
        <form action="/login" method="POST">
            <input type="text" name="email" placeholder="Enter Email" required><br><br>
            <input type="password" name="password" placeholder="Enter Password" required><br><br>
            <input type="submit" value="Login">
        </form>
    `);
});

// Secure Signup Route
app.post('/signup', async (req, res) => {
    const { email, password } = req.body;

    if (!validator.isEmail(email)) {
        logger.warn(`Failed Signup Attempt: Invalid email format submitted - ${email}`);
        return res.status(400).send('<h3>Error: Invalid email format! Input Sanitized.</h3><a href="/">Go Back</a>');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        usersDB.push({ email, password: hashedPassword });
        
        logger.info(`Successful Signup: User ${email} registered.`);
        res.send(`<h3>User Registered Successfully!</h3><p><b>Hashed Password stored in DB:</b> ${hashedPassword}</p><a href="/">Go Back to Login</a>`);
    } catch (error) {
        logger.error(`Signup Error: ${error.message}`);
        res.status(500).send('Server Error');
    }
});

// Secure Login Route
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    const user = usersDB.find(u => u.email === email);
    if (!user) {
        logger.warn(`Failed Login Attempt: User not found - ${email}`);
        return res.status(400).send('User not found! <a href="/">Go Back</a>');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        logger.warn(`Failed Login Attempt: Incorrect password for user - ${email}`);
        return res.status(400).send('Invalid Credentials! <a href="/">Go Back</a>');
    }

    const token = jwt.sign({ email: user.email }, SECRET_KEY, { expiresIn: '1h' });
    
    logger.info(`Successful Login: User ${email} logged in. JWT generated.`);
    res.send(`<h2>Login Successful!</h2><p><b>Your Secure JWT Token:</b></p><textarea rows="4" cols="50">${token}</textarea><br><br><a href="/">Logout</a>`);
});

app.listen(3000, () => console.log('Secure Server running on port 3000 with Winston Logging.'));