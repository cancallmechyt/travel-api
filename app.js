const express = require('express')
const cors = require('cors')
const app = express()
const bodyParser = require('body-parser')
const jsonParser = bodyParser.json()
const bcrypt = require('bcrypt');
const saltRounds = 10;
const jwt = require('jsonwebtoken');
const secret = 'Fullstack-Login'
require('dotenv').config()
const mysql = require('mysql2')

const connection = mysql.createConnection(process.env.DATABASE_URL)

app.use(cors({
    origin: 'http://localhost:3000', // ให้เฉพาะ domain ที่ระบุเข้าถึงได้
    methods: ['GET', 'POST'], // อนุญาตเฉพาะ method ที่ระบุ
    allowedHeaders: ['Content-Type', 'Authorization'] // อนุญาตเฉพาะ header ที่ระบุ
}));

//Home page
app.get('/', (req, res) => {
    console.log('Hello world')
    res.send('Hello world!!')
})

//Register API
app.post('/register', jsonParser, function (req, res, next) {
    bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
        connection.execute(
            'INSERT INTO users (fname, lname, email, username, password, avatar) VALUES (?, ?, ?, ?, ?, ?)',
            [req.body.fname, req.body.lname, req.body.email, req.body.username, hash, req.body.avatar],
            function (err, results, fields) {
                if (err) {
                    res.json({ status: 'error', message: err })
                    return
                }
                res.json({ status: 'success' })
            }
        );
    });
})

//login API
app.post('/login', jsonParser, function (req, res, next) {
    connection.execute(
        'SELECT * FROM users WHERE email=?',
        [req.body.email],
        function (err, users, fields) {
            if (err) { res.json({ status: 'error', message: err }); return }
            if (users.length == 0) { res.json({ status: 'error', message: 'no users found' }); return }
            bcrypt.compare(req.body.password, users[0].password, function (err, isLogin) {
                if (isLogin) {
                    var token = jwt.sign({ email: users[0].email }, secret, { expiresIn: '1h' });
                    res.json({ status: 'success', message: 'login successful', token })

                } else {
                    res.json({ status: 'error', message: 'login failed' })
                }
            });
        }
    );
})

//authe Token
app.post('/authen', jsonParser, function (req, res, next) {
    try {
        const token = req.headers.authorization.split(' ')[1]
        var decoded = jwt.verify(token, secret);
        res.json({ status: 'success', decoded })
        res.json({ decoded });
    } catch (error) {
        res.json({ status: 'error', message: error.message })
    }
})

app.listen(4040, function () {
    console.log('CORS-enabled web server listening on port 4040')
})