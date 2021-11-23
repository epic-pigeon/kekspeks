const mongoose = require('mongoose');

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
    messages: [{
        fromLogin: {
            type: String,
            required: true,
        },
        content: {
            type: Buffer,
            required: true,
        },
    }],
});

module.exports = mongoose.model("Group", groupSchema);
