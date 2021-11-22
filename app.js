const express = require('express'), app = express();
const helmet = require('helmet');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const mongoose = require('mongoose');
const config = require('./config');
const jwt = require('jsonwebtoken');
const User = require('./models/user');
const Message = require('./models/message');
global.TextEncoder = require("util").TextEncoder;

app.use(helmet());
app.use(cors({
    credentials: false,
    origin: "*",
    maxAge: 10 * 60
}));
app.use(bodyParser.urlencoded({extended: false}));
app.use(bodyParser.json());

app.use(async (req, res, next) => {
    const accessToken = req.body['access_token'] || req.headers['x-access-token'];
    if (accessToken) {
        try {
            const {id} = jwt.verify(accessToken, config.JWT_SECRET);
            req.user = await User.findById(id);
            return next();
        } catch (e) {
            return res.status(401).send("Bad token");
        }
    } else return next();
});

app.post("/api/login", async (req, res, next) => {
    const {login, password} = req.body;
    if (typeof login !== "string" || typeof password !== "string") {
        return res.status(401).send("Wrong login or password");
    }
    const users = await User.find({login});
    if (users.length === 0) {
        return res.status(401).send("Wrong login or password");
    } else if (users.length >= 2) {
        // wtf
        return res.status(401).send("Wrong login or password");
    } else {
        let user = users[0];
        crypto.pbkdf2(password, login, 100, 64, 'sha512', (err, key) => {
            if (err) {
                return res.status(500).send("Server error");
            }
            if (user.password === key.toString('hex')) {
                let token = jwt.sign({id: user._id}, config.JWT_SECRET, {expiresIn: "7d"});
                return res.status(200).send({token});
            } else {
                return res.status(401).send("Wrong login or password");
            }
        })
    }
});

app.post("/api/signup", async (req, res, next) => {
    const {login, password} = req.body;
    if (typeof login !== "string" || !login.match(/^[a-zA-Z_$]{3,20}$/)
     || typeof password !== "string" || password.length < 8 || password.length > 40) {
        return res.status(401).send("Bad login or password");
    }
    let user = await User.findOne({login});
    if (user) return res.status(401).send("This login already exists");
    crypto.pbkdf2(password, login, 100, 64, 'sha512', (err, encrypted) => {
        if (err) {
            return res.status(500).send("Server error");
        }
        crypto.generateKeyPair('rsa', {
            modulusLength: 4096,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem',
                cipher: 'aes-256-cbc',
                passphrase: password,
            }
        }, async (err, publicKey, privateKey) => {
            if (err) {
                return res.status(500).send("Server error");
            }
            let user = new User({login, password: encrypted.toString('hex'), publicKey});
            await user.save();
            let token = jwt.sign({id: user._id}, config.JWT_SECRET, {expiresIn: "7d"});
            return res.status(200).send({token, privateKey: privateKey.toString()});
        });
    });
});

app.post("api/send-message", async (req, res, next) => {
    if (!req.user) res.status(403).send("Unauthorized");
    const {to_login, text} = req.body;
    let toUser = await User.findOne({login: to_login});
    if (!toUser) res.status(401).send("Login not found");
    let buffer = Buffer.from(text);
    let encrypted = crypto.publicEncrypt(toUser.publicKey, buffer);
    let messageObj = new Message({
        fromLogin: req.user.login,
        toLogin: toUser.login,
        message: encrypted,
    });
    await messageObj.save();
    res.status(200).send("OK");
});

app.use((req, res, next) => {
    res.status(404).end('Endpoint not found');
});

app.use((error, req, res, next) => {
    console.error(error);
    res.status(500).send("Server error");
});

mongoose.connect(config.MONGO_URI, { useNewUrlParser: true })
.then(() => console.log('Connection to MongoDB was successful'))
.catch(err => {
    console.error(err);
    process.exit(1);
});

app.listen(config.APP_PORT, () => {
    console.log('Server up and running');
});
