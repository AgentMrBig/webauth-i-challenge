const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const session = require('express-session')
// ----------------------------------
// this is where we add bcryptjs for our
// use...
const bcrypt = require('bcryptjs');
// ----------------------------------

const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');

const sessionOptions = {
    name: 'mycookie',
    secret: 'heyitsalambdacookie',
    cookie: {
        maxAge: 1000 * 60 * 60,
        secure: false,
        httpOnly: true
    },
    resave: false,
    saveUninitialized: false
}

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());
server.use(session(sessionOptions))

server.get('/', (req, res) => {
    res.send("It's alive!");
});


server.post('/api/register', (req, res) => {
    let user = req.body;
    const hash = bcrypt.hashSync(user.password, 10);
    user.password = hash;

    Users.add(user)
        .then(saved => {
            res.status(201).json(saved);
        })
        .catch(error => {
            res.status(500).json(error);
        });
});

server.post('/api/login', validate, (req, res) => {
    let { username, password } = req.body;

    Users.findBy({ username })
        .first()
        .then(user => {
            if (user && bcrypt.compareSync(password, user.password)) {
                req.session.user = user;
                res.status(200).json({
                    message: `Welcome ${user.username}! you have a cookie dude!`,

                })
            } else {
                res.status(401).json({ message: 'Invalid Credentials' });
            }
        })
        .catch(error => {
            res.status(500).json(error);
        });
});


server.get('/api/users', validate, (req, res) => {

    Users.find()
        .then(users => {
            res.json(users);
        })
        .catch(err => res.send(err));
});

function validate(req, res, next) {
    const { username, password } = req.headers;

    // if both the username and password headers are found...
    if (username && password) {
        // look up the user
        Users.findBy({ username })
            .first()
            .then(user => {
                // if the user is found in the DB
                // AND the password supplied hashes to the same hash
                // that is stored...
                if (user && bcrypt.compareSync(password, user.password)) {
                    // go to the next middleware handler
                    next();
                } else {
                    // otherwise, respond with a 401
                    res.status(401).json({ message: "Invalid credentials" });
                }
            })
            // if our DB model module has a problem with the request,
            // we will just return a 500 (kinda lazy of us, but it's just
            // a demo)
            .catch(err => {
                res.status(500).json({ message: "unexpected error" });
            });
        // if either the username or the password are not supplied in 
        // the request headers, respond with a 400.
    } else {
        res.status(400).json({ message: "no credentials provided" });
    }
}

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));