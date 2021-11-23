const express = require('express'), app = express();
const helmet = require('helmet');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const mongoose = require('mongoose');
const config = require('./config');
const jwt = require('jsonwebtoken');
const User = require('./models/user');
const Group = require('./models/group');
global.TextEncoder = require("util").TextEncoder;

function createError(status, msg) {
    let res = new Error(msg);
    res.status = status;
    return res;
}

function createInternalError(msg = "Server error") {
    return createError(500, msg);
}

function verifyFieldSignature(
    req,
    signPublicKey,
    fieldName,
    signatureFieldName = fieldName + "_signature",
    timestampFieldName = signatureFieldName + "_timestamp",
) {
    let value = req.body[fieldName];
    if (typeof value !== "string") throw createError(401, `${fieldName} should be a string`);
    let signature = req.body[signatureFieldName];
    if (typeof signature !== "string") throw createError(401, `${signatureFieldName} should be a string`);
    let timestamp = req.body[timestampFieldName];
    if (typeof timestamp !== "string" && typeof timestamp !== "number")
        throw createError(401, `${timestampFieldName} should be a string or a number`);
    timestamp = +timestamp;
    if (!(Date.now() > timestamp && timestamp + 5 * 60 * 1000 > Date.now())) {
        throw createError(401, "Outdated signature");
    }
    let verified = crypto.verify(
        "sha256",
        Buffer.concat([Buffer.from(timestamp + ""), Buffer.from([0]), Buffer.from(value)]),
        signPublicKey,
        Buffer.from(signature, "base64")
    );
    if (!verified) {
        throw createError(401, "Bad signature");
    }
    return value;
}

function getRequest(req) {
    let result;
    try {
        result = JSON.parse(req.body["request"]);
    } catch (e) {
        throw createError(401, "Bad request");
    }
    if (!result instanceof Object) {
        throw createError(401, "Bad request");
    }
    if (req.user) {
        verifyFieldSignature(req, req.user.signPublicKey, "request");
    }
    return result;
}

app.use(helmet());
app.use(cors({
    credentials: false,
    origin: "*",
    maxAge: 10 * 60
}));
app.use(bodyParser.urlencoded({extended: false}));
app.use(bodyParser.json());

app.use(async (req, res, next) => {
    const accessToken = req.body['access_token'];
    if (accessToken && typeof accessToken === "string") {
        const {id} = jwt.verify(accessToken, config.JWT_SECRET);
        let user = await User.findById(id);
        if (!user) createError(401, "Bad user ID");
        req.user = user;
        return next();
    } else return next();
});

app.post("/api/login", async (req, res, next) => {
    const {login, password} = req.body;
    if (typeof login !== "string" || typeof password !== "string") {
        return res.status(401).send("Wrong login or password");
    }
    const user = await User.findOne({login});
    if (!user) {
        return res.status(401).send("Wrong login or password");
    } else {
        verifyFieldSignature(req, user.signPublicKey, "login");
        crypto.pbkdf2(password, login, 50_000, 64, 'sha512', (err, key) => {
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
    const {login, password, sign_public_key, message_public_key} = req.body;
    if (typeof login !== "string" || !login.match(/^[a-zA-Z_$]{3,20}$/)
     || typeof password !== "string" || password.length < 8 || password.length > 40) {
        return res.status(401).send("Bad login or password");
    }
    let user = await User.findOne({login});
    if (user) return res.status(401).send("This login already exists");
    if (typeof sign_public_key !== "string") return res.status(401).send("Invalid sign key");
    try {
        crypto.createPublicKey(sign_public_key);
    } catch (e) {
        return res.status(401).send("Invalid sign key");
    }
    if (typeof message_public_key !== "string") return res.status(401).send("Invalid message key");
    try {
        crypto.createPublicKey(message_public_key);
    } catch (e) {
        return res.status(401).send("Invalid message key");
    }
    verifyFieldSignature(req, sign_public_key, "login");
    crypto.pbkdf2(password, login, 50_000, 64, 'sha512', async (err, encrypted) => {
        if (err) {
            return res.status(500).send("Server error");
        }
        let user = new User({
            login,
            password: encrypted.toString('hex'),
            signPublicKey: sign_public_key,
            messagePublicKey: message_public_key,
        });
        await user.save();
        let token = jwt.sign({id: user._id}, config.JWT_SECRET, {expiresIn: "7d"});
        return res.status(200).send({token});
    });
});

app.post("/api/create-group", async (req, res, next) => {
    if (!req.user) return res.status(403).send("Unauthorized");
    let {name} = getRequest(req);
    if (typeof name !== "string") return res.status(401).send("Bad name");
    name = name.trim();
    if (name.length === 0) return res.status(401).send("Bad name");
    let group = new Group({
        name: name,
        ownerLogin: req.user.login,
    });
    await group.save();
    return res.status(200).send("OK");
});

/*app.post("/api/send-message", async (req, res, next) => {
    if (!req.user) return res.status(403).send("Unauthorized");
    const {to_login, timestamp, text, signature} = req.body;
    if (typeof to_login !== "string" || (typeof timestamp !== "string" && typeof timestamp !== "number")
        || typeof text !== "string" || typeof signature !== "string") {
        return res.status(401).send("Bad request");
    }
    // NaN check!
    if (!(Date.now() > +timestamp && +timestamp + 5 * 60 * 1000 > Date.now())) {
        return res.status(401).send("Message expired");
    }
    let toUser = await User.findOne({login: to_login});
    if (!toUser) return res.status(401).send("Login not found");
    let verified = crypto.verify(
        "sha256",
        Buffer.concat([Buffer.from((+timestamp) + ""), Buffer.from([0]), Buffer.from(text)]),
        req.user.signPublicKey,
        Buffer.from(signature, "base64")
    );
    if (!verified) {
        return res.status(401).send("Bad signature");
    }
    let buffer = Buffer.from(text);
    let encrypted = crypto.publicEncrypt({
        key: toUser.messagePublicKey,
        oaepHash: "sha256"
    }, buffer);
    let messageObj = new Message({
        fromLogin: req.user.login,
        toLogin: toUser.login,
        message: encrypted,
    });
    await messageObj.save();
    return res.status(200).send("OK");
});*/

app.use((req, res, next) => {
    res.status(404).end('Endpoint not found');
});

app.use((error, req, res, next) => {
    console.error(error);
    if (error.status) {
        res.status(error.status).send(error.message);
    } else {
        res.status(500).send("Server error");
    }
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
