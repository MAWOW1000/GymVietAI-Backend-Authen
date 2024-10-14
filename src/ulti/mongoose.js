module.exports = {
    multiMongooseToObject(mongooses) {
        return mongooses.map((mongoose) => mongoose.toObject());
    },
    mongooseToObject(mongoose) {
        return mongoose.toObject();
    },
};
