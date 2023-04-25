var express = require('express')
var cors = require('cors')
var app = express()
var bodyParser = require('body-parser')
var jsonParser = bodyParser.json()
var jwt = require('jsonwebtoken');
const secret = 'po'
const bcrypt = require('bcrypt');
const saltRounds = 10;

app.use(cors())

const mysql = require('mysql2');

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    database: 'travelweb'
});

app.get('/users', (req, res) => {
    connection.query(
        'SELECT * FROM users',
        function(err, results, fields) {
            console.log(results)
            res.send(results)
        }
    )
})

app.post('/register', jsonParser, function (req, res, next) {
    bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
        // Store hash in your password DB.
        connection.execute(
            'INSERT INTO users (fname, lname, email, username, password, avatar) VALUE (?, ?, ?, ?, ?, ?)',
            [req.body.fname, req.body.lname, req.body.email,req.body.username, hash, req.body.avatar ],
            function (err, results, fields) {
                if (err) {
                    res.json({ status: 'error', message: err })
                    return
                }
                res.json({ status: 'ok' })
            }
        );
    });
})

app.post('/login', jsonParser, function (req, res, next) {
    connection.execute(
        'SELECT * FROM users WHERE email=?',
        [req.body.email],
        function (err, users, fields) {
            if (err) { res.json({ status: 'error', message: err }); return }
            if (users.length == 0) { res.json({ status: 'error', message: 'no user found' }); return }
            bcrypt.compare(req.body.password, users[0].password, function (err, isLogin) {
                if (isLogin) {
                    var token = jwt.sign({ email: users[0].email }, secret, { expiresIn: '1h' });
                    res.json({ status: 'ok', message: 'login success', token })
                } else {
                    res.json({ status: 'error', message: 'login fail' })
                }
            });
        }
    );
})

app.post('/authen', jsonParser, function (req, res, next) {
    try {
        const token = req.headers.authorization.split(' ')[1]
        var decoded = jwt.verify(token, secret);
        res.json({status: 'ok', decoded})
    } catch (error) {
        res.json({status: 'error', message: err.message})
    }
})

app.listen(3333, function () {
    console.log('CORS-enabled web server listening on port 3333')
})