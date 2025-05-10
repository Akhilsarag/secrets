const express = require('express');
const bodyParser = require('body-parser');
const encrypt = require('mongoose-encryption');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(cookieParser());

const mongoose = require('mongoose');
mongoose.connect('mongodb://localhost:27017/secrets');

const trySchema = new mongoose.Schema({
    email: String,
    password: String
});

const secretKey = 'Thisislittlesecret.';
const jwtSecret = 'jwtSuperSecretKey'; // In real apps, store this in .env

trySchema.plugin(encrypt, { secret: secretKey, encryptedFields: ['password'] });

const User = mongoose.model('User', trySchema);

function authenticateToken(req, res, next) {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login');

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) return res.redirect('/login');
        req.user = user;
        next();
    });
}

app.get('/', (req, res) => {
    res.render('home');
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    const newUser = new User({
        email: req.body.email,
        password: req.body.password
    });

    try {
        await newUser.save();
        res.redirect('/login');
    } catch (err) {
        console.log(err);
        res.redirect('/register');
    }
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', async (req, res) => {
    const email = req.body.email;
    const password = req.body.password;

    try {
        const foundUser = await User.findOne({ email: email });
        if (!foundUser) return res.send('No user found with this email');

        if (foundUser.password === password) {
            const userPayload = { email: foundUser.email };
            const token = jwt.sign(userPayload, jwtSecret, { expiresIn: '1h' });

            res.cookie('token', token, { httpOnly: true, secure: false }); // secure: true in production
            res.redirect('/secrets');
        } else {
            res.send('Incorrect password');
        }
    } catch (err) {
        console.log(err);
        res.redirect('/login');
    }
});

app.get('/secrets', authenticateToken, (req, res) => {
    const dummySecrets = [
        { content: 'I love pizza' },
        { content: 'I sing in the shower' }
    ];
    res.render('secrets', { secrets: dummySecrets });
});

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/logout');
});

app.listen(3000, () => {
    console.log('server started');
});
