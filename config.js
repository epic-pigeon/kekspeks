exports.DEBUG = (process.env.NODE_ENV === 'development');
exports.APP_PORT = +process.env.PORT || 8080;
exports.JWT_SECRET = process.env.JWT_SECRET;
exports.MONGO_URI = process.env.MONGO_URI;
