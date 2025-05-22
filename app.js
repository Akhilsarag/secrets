const express = require('express');
const bodyParser = require('body-parser');
const encrypt = require('mongoose-encryption');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');

const app = express();
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(cookieParser());

// MongoDB connection
mongoose.connect('mongodb+srv://user3:Akhil1234@cluster0.c9dkcry.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0');

// Schema and Encryption
const trySchema = new mongoose.Schema({
    email: String,
    password: String,
    secrets: [{ content: String }]
});
const secretKey = 'Thisislittlesecret.';
const jwtSecret = 'jwtSuperSecretKey';

trySchema.plugin(encrypt, { secret: secretKey, encryptedFields: ['password'] });
const User = mongoose.model('User', trySchema);

// Middleware to protect routes
function authenticateToken(req, res, next) {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login');
    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) return res.redirect('/login');
        req.user = user;
        next();
    });
}

// Validation functions
function isStrongPassword(password) {
    const strongRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!]).{8,}$/;
    return strongRegex.test(password);
}

function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Routes
app.get('/', (req, res) => {
    res.render('home');
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    const { email, password } = req.body;

    if (!isValidEmail(email)) {
        return res.send('Invalid email format.');
    }

    if (!isStrongPassword(password)) {
        return res.send('Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.');
    }

    const newUser = new User({ email, password });

    try {
        await newUser.save();
        res.redirect('/login');
    } catch (err) {
        console.log(err);
        res.redirect('/register');
    }
});

// ✅ LOGIN: Send error messages to login page and preserve email
app.get('/login', (req, res) => {
    res.render('login', { error: null, email: '' });
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const foundUser = await User.findOne({ email });

        if (!foundUser) {
            return res.render('login', { error: 'Email not found. Please register first.', email });
        }

        if (foundUser.password !== password) {
            return res.render('login', { error: 'Incorrect password. Please try again.', email });
        }

        const token = jwt.sign({ email: foundUser.email }, jwtSecret, { expiresIn: '1h' });
        res.cookie('token', token, { httpOnly: true });
        res.redirect('/secrets');

    } catch (err) {
        console.log(err);
        res.render('login', { error: 'Something went wrong. Please try again.', email });
    }
});

app.get('/secrets', authenticateToken, async (req, res) => {
    try {
        const user = await User.findOne({ email: req.user.email });
        res.render('secrets', { secrets: user.secrets || [] });
    } catch (err) {
        console.log(err);
        res.redirect('/');
    }
});

app.get('/submit', authenticateToken, (req, res) => {
    res.render('submit');
});

app.post('/submit', authenticateToken, async (req, res) => {
    const submittedSecret = req.body.secret;
    const userEmail = req.user.email;

    try {
        await User.findOneAndUpdate(
            { email: userEmail },
            { $push: { secrets: { content: submittedSecret } } }
        );
        res.redirect('/secrets');
    } catch (err) {
        console.log(err);
        res.redirect('/submit');
    }
});

app.post('/edit', authenticateToken, async (req, res) => {
    const { id, newContent } = req.body;

    try {
        const user = await User.findOne({ email: req.user.email });
        const secret = user.secrets.id(id);
        if (secret) {
            secret.content = newContent;
            await user.save();
        }
        res.redirect('/secrets');
    } catch (err) {
        console.log(err);
        res.redirect('/secrets');
    }
});

app.post('/delete', authenticateToken, async (req, res) => {
    const secretId = req.body.id;

    try {
        await User.updateOne(
            { email: req.user.email },
            { $pull: { secrets: { _id: secretId } } }
        );
        res.redirect('/secrets');
    } catch (err) {
        console.log(err);
        res.redirect('/secrets');
    }
});

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/');
});

app.listen(3000, () => {
    console.log('Server started on port 3000');
});
