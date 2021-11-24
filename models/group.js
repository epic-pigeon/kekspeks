const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
    fromLogin: {
        type: String,
        required: true,
    },
    content: {
        type: Buffer,
        required: true,
    },
    salt: {
        type: Buffer,
        required: true,
    },
}, {timestamps: true});

const groupSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    ownerLogin: {
        type: String,
        required: true,
    },
    memberLogins: [{
        type: String,
        required: true,
    }],
    messages: [messageSchema],
}, {timestamps: true});

module.exports = mongoose.model("Group", groupSchema);
