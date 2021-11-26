const mongoose = require('mongoose');

const invitationSchema = new mongoose.Schema({
    groupId: {
        type: String,
        required: true,
    },
    key: {
        type: Buffer,
        required: true,
    },
}, {timestamps: true});

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
    requestChallenges: [{
        type: String,
    }],
    requestChallengeTimestamps: [{
        type: Date,
    }],
    invitations: [invitationSchema],
}, {timestamps: true});

module.exports = mongoose.model('User', userSchema);
