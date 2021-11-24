const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    login: {
        type: String,
        required: true,
        unique: true,
    },
    password: {
        type: String,
        required: true,
    },
    signPublicKey: {
        type: String,
        required: true
    },
    messagePublicKey: {
        type: String,
        required: true
    },
    requestChallenge: {
        type: String,
        required: false,
    },
    requestChallengeTimestamp: {
        type: Date,
        required: false,
    },
}, {timestamps: true});

module.exports = mongoose.model('User', userSchema);
