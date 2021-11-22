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
    publicKey: {
        type: String,
        required: true
    },
}, {timestamps: true});

module.exports = mongoose.model('User', userSchema);