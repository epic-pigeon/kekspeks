const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
    fromLogin: {
        type: String,
        required: true,
    },
    toLogin: {
        type: String,
        required: true,
    },
    message: {
        type: Buffer,
        required: true
    },
}, {timestamps: true});

module.exports = mongoose.model('Message', messageSchema);
