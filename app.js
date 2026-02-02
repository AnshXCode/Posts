import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import User from './models/user.js';


// const username = 'goyalanshuman4_db_user';
// const password = 'CbRfdwfRf1mlZXqV';
const app = express();

app.set('view engine', 'ejs');

app.use(express.json());

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(express.static('public'));  // for static files    

app.get('/', (req, res) => {
    res.render('login');
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.get('/home', verifyToken, (req, res) => {
    res.render(req.username);
});

app.use(verifyToken);

function verifyToken(req, res, next){
    const token = req.cookies.token;
    if(!token) return res.redirect('/login');
    jwt.verify(token, 'secretKey', (err, decoded) => {
        if(err) return res.redirect('/login');
        req.username = decoded.username;
        next();
    });
}

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.send('Please register first');
    bcrypt.compare(password, user.password, (err, result) => {
        if (err) return res.send('Something went wrong');
        if (!result) return res.send('Invalid password');
        res.cookie('token', jwt.sign({ username }, 'secretKey'), { httpOnly: true });
        res.redirect('/home');
    });
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.send('Username, email and password required');
    }
    try {
        const hash = await bcrypt.hash(password, 10);
        await User.create({ username, email, password: hash });
        res.redirect('/login');
    } catch (err) {
        if (err.code === 11000) return res.send('Username or email already taken');
        res.send('Registration failed');
    }
});

mongoose.connect(process.env.MONGODB_URI).then(() => {
    console.log('Connected to MongoDB')
    app.listen(3001, () => {
        console.log('Server is running on port 3001');
    })
}).catch((err) => console.error('MongoDB:', err.message));