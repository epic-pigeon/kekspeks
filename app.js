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
    if (typeof value !== "string") throw createError(400, `${fieldName} should be a string`);
    let signature = req.body[signatureFieldName];
    if (typeof signature !== "string") throw createError(400, `${signatureFieldName} should be a string`);
    let timestamp = req.body[timestampFieldName];
    if (typeof timestamp !== "string" && typeof timestamp !== "number")
        throw createError(400, `${timestampFieldName} should be a string or a number`);
    timestamp = +timestamp;
    if (!(Date.now() > timestamp && timestamp + 10 * 1000 > Date.now())) {
        throw createError(400, "Outdated signature");
    }
    let verified = crypto.verify(
        "sha256",
        Buffer.concat([Buffer.from(timestamp + ""), Buffer.from([0]), Buffer.from(value)]),
        signPublicKey,
        Buffer.from(signature, "base64")
    );
    if (!verified) {
        throw createError(400, "Bad signature");
    }
    return value;
}

async function verifyRequestChallenge(req) {
    if (!req.user) throw createError(401, "Unauthorized");
    if (req.user.req)
        throw createError(400, "N");
    let {challenge_signature: signature, challenge} = req.body;
    if (typeof signature !== "string" || typeof challenge !== "string")
        throw createError(400, "Bad data");
    let idx = req.user.requestChallenges.indexOf(challenge);
    if (idx === -1) throw createError(400, "Challenge not found");
    if (req.user.requestChallengeTimestamps[idx].getTime() + 60 * 1000 < Date.now())
        throw createError(400, "Challenge outdated");
    let verified = crypto.verify(
        "sha256",
        Buffer.from(challenge),
        req.user.signPublicKey,
        Buffer.from(signature, "base64")
    );
    req.user.requestChallenges.splice(idx, 1);
    req.user.requestChallengeTimestamps.splice(idx, 1);
    await req.user.save();
    if (!verified) throw createError(400, "Bad challenge");
}

function groupAccessibleTo(login) {
    return {
        $or: [
            {
                ownerLogin: login
            },
            {
                memberLogins: { $elemMatch: { $in: [login] } }
            }
        ]
    };
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
        if (!user) createError(400, "Bad user ID");
        req.user = user;
        return next();
    } else return next();
});

app.post("/api/me", async (req, res, next) => {
    await verifyRequestChallenge(req);
    return res.status(200).send({login: req.user.login})
});

app.post("/api/login", async (req, res, next) => {
    const {login, password} = req.body;
    if (typeof login !== "string" || typeof password !== "string") {
        return res.status(400).send("Wrong login or password");
    }
    const user = await User.findOne({login});
    if (!user) {
        return res.status(400).send("Wrong login or password");
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
                return res.status(400).send("Wrong login or password");
            }
        })
    }
});

app.post("/api/signup", async (req, res, next) => {
    const {login, password, sign_public_key, message_public_key} = req.body;
    if (typeof login !== "string" || !login.match(/^[a-zA-Z_$]{3,20}$/)
     || typeof password !== "string" || password.length < 8 || password.length > 40) {
        return res.status(400).send("Bad login or password");
    }
    let user = await User.findOne({login});
    if (user) return res.status(400).send("This login already exists");
    if (typeof sign_public_key !== "string") return res.status(400).send("Invalid sign key");
    try {
        crypto.createPublicKey(sign_public_key);
    } catch (e) {
        return res.status(400).send("Invalid sign key");
    }
    if (typeof message_public_key !== "string") return res.status(400).send("Invalid message key");
    try {
        crypto.createPublicKey(message_public_key);
    } catch (e) {
        return res.status(400).send("Invalid message key");
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

app.post("/api/challenge", async (req, res, next) => {
    if (!req.user) return res.status(403).send("Unauthorized");
    let challenge = crypto.randomBytes(64).toString("hex");
    for (let i = 0; i < req.user.requestChallenges.length; i++) {
        if (req.user.requestChallengeTimestamps[i].getTime() + 60 * 1000 < Date.now()) {
            req.user.requestChallenges.splice(i, 1);
            req.user.requestChallengeTimestamps.splice(i, 1);
            i--;
        }
    }
    if (req.user.requestChallenges.length < 10) {
        req.user.requestChallenges.push(challenge);
        req.user.requestChallengeTimestamps.push(new Date());
    } else {
        res.status(400).send("Too many challenges");
    }
    await req.user.save();
    return res.status(200).send({challenge});
});

app.post("/api/create-group", async (req, res, next) => {
    await verifyRequestChallenge(req);
    let {name} = req.body;
    if (typeof name !== "string") return res.status(400).send("Bad name");
    name = name.trim();
    if (name.length === 0) return res.status(400).send("Bad name");
    let group = new Group({
        name: name,
        ownerLogin: req.user.login,
    });
    await group.save();
    return res.status(200).send({
        _id: group._id,
        name: group.name,
        ownerLogin: group.ownerLogin,
        memberLogins: group.memberLogins,
    });
});

app.post("/api/invite", async (req, res, next) => {
    await verifyRequestChallenge(req);
    let {login, group_id: groupId, key} = req.body;
    if (typeof login !== "string" || typeof groupId !== "string" || typeof key !== "string") {
        return res.status(400).send("Bad data");
    }
    let group = await Group.findOne({_id: groupId, ownerLogin: req.user.login}, {messages: 0});
    if (!group) {
        return res.status(400).send("Group not found or you are not the owner");
    }
    if (login === req.body.login) {
        return res.status(400).send(":)");
    }
    if (group.memberLogins.indexOf(login) !== -1) {
        return res.status(400).send("The user is already in the group");
    }
    let user = await User.findOneAndUpdate(
        {login, invitations: {$not: {$elemMatch: {groupId}}}},
        {
            $push: {
                invitations: {
                    $each: [{
                        groupId: group._id,
                        key: Buffer.from(key, 'base64'),
                    }],
                    $position: 0
                }
            }
        },
        {new: true, projection: {login, invitations: {$slice: [0, 1]}}}
    );
    if (!user) {
        return res.status(400).send("No such user exists or user already invited");
    }
    notify(req.body.login, {
        type: "invitation",
        invitation: user.invitations[0]
    });
    return res.status(200).send(user.invitations[0]);
});

app.post("/api/get-invites", async (req, res, next) => {
    await verifyRequestChallenge(req);
    let {skip, count} = req.body;
    skip = +skip;
    count = +count;
    if (!(skip >= 0)) skip = 0;
    if (!(count >= 1)) count = 1;
    if (!(count <= 20)) count = 20;
    let user = await User.findOne({login: req.user.login}, {invitations: {$slice: [skip, count]}});
    if (!user) {
        return res.status(500).send("hm");
    }
    return res.status(200).send({invitations: user.invitations});
});

app.post("/api/remove-invite", async (req, res, next) => {
    await verifyRequestChallenge(req);
    let {group_id: groupId, accept} = req.body;
    if (typeof accept === "string") accept = accept === "true";
    if (typeof groupId !== "string" || typeof accept !== "boolean") {
        return res.status(400).send("Bad request");
    }
    let group = await Group.findById(groupId, 'name ownerLogin memberLogins');
    if (!group) {
        return res.status(400).send("Group does not exist");
    }
    let l = req.user.invitations.length;
    req.user.invitations = req.user.invitations.filter(i => i.groupId !== groupId);
    await req.user.save();
    if (req.user.invitations.length === l) {
        return res.status(400).send("No such invitation");
    }
    if (accept) {
        group.memberLogins = [...new Set([...group.memberLogins, req.user.login])];
        await group.save();
    }
    return res.status(200).send(group);
});

app.post("/api/send-message", async (req, res, next) => {
    await verifyRequestChallenge(req);
    let {id, message, salt} = req.body;
    if (typeof id !== "string" || typeof message !== "string" || typeof salt !== "string") {
        return res.status(400).send("Bad request");
    }
    let group = await Group.findOneAndUpdate(Object.assign({_id: id}, groupAccessibleTo(req.user.login)), {
        $push: {
            messages: {
                $each: [{
                    fromLogin: req.user.login,
                    content: Buffer.from(message, "base64"),
                    salt: Buffer.from(salt, "base64"),
                }],
                $position: 0
            }
        }
    }, {new: true, projection: {ownerLogin: 1, memberLogins: 1, messages: {$slice: [0, 1]}}});
    if (!group) {
        return res.status(400).send("Group not found");
    }
    for (let login of [group.ownerLogin, ...group.memberLogins]) {
        notify(login, {
            type: "message",
            message: group.messages[0],
            groupId: group._id,
        });
    }
    return res.status(200).send(group.messages[0]);
});

app.post("/api/groups", async (req, res, next) => {
    await verifyRequestChallenge(req);
    let {skip, count} = req.body;
    skip = +skip;
    count = +count;
    if (!(skip >= 0)) skip = 0;
    if (!(count >= 1)) count = 1;
    if (!(count <= 20)) count = 20;
    let groups = await Group.find(groupAccessibleTo(req.user.login), '_id name ownerLogin memberLogins').skip(skip).limit(count).sort([['updatedAt', 'desc']]);
    return res.status(200).send({groups});
});

app.post("/api/messages", async (req, res, next) => {
    await verifyRequestChallenge(req);
    let {group_id: groupId, skip, count} = req.body;
    skip = +skip;
    count = +count;
    if (!(skip >= 0)) skip = 0;
    if (!(count >= 1)) count = 1;
    if (!(count <= 50)) count = 50;
    let group = await Group.findOne(Object.assign({_id: groupId}, groupAccessibleTo(req.user.login)), {messages: {$slice: [skip, count]}});
    if (!group) {
        return res.status(400).send("Group not found");
    }
    return res.status(200).send({messages: group.messages});
});

app.post("/api/user", async (req, res, next) => {
    await verifyRequestChallenge(req);
    let {login} = req.body;
    if (!login || typeof login !== "string") {
        return res.status(400).send("Bad login");
    }
    let result = await User.findOne({login}, 'login signPublicKey messagePublicKey');
    if (!result) return res.status(400).send("Bad login");
    return res.status(200).send(result);
});

let polling = {};

function notify(userLogin, event) {
    if (!polling[userLogin]) return;
    while (polling[userLogin].length > 0) {
        polling[userLogin].shift()(event);
    }
    polling[userLogin] = undefined;
}

app.post("/api/poll", async (req, res, next) => {
    await verifyRequestChallenge(req);
    if (!polling[req.user.login]) polling[req.user.login] = [];
    let resolved = false;
    let func = event => {
        res.status(200).send(event);
        resolved = true;
    }
    polling[req.user.login].push(func);
    setTimeout(() => {
        if (!resolved) {
            let idx = polling[req.user.login].indexOf(func);
            polling[req.user.login].splice(idx, 1);
            res.status(408).send("Poll timeout");
        }
    }, 60_000);
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
    res.status(404).end(`Endpoint not found: ${req.path}`);
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
