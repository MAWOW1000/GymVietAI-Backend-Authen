const mongoose = require('mongoose');
var mongoose_delete = require('mongoose-delete');
const slug = require('mongoose-slug-updater');

const Schema = mongoose.Schema;

const NewSchema = new Schema(
    {
        title: String,
        description: String,
        img: String,
        slug: { type: String, slug: 'title', unique: true },
    },
    {
        timestamps: true,
    },
);

NewSchema.query.sortSpecial = function (req) {
    if (req.query.hasOwnProperty('_sort')) {
        return this.sort({
            [req.query.field]: req.query.type,
        });
    }
    return this;
};

mongoose.plugin(slug);
NewSchema.plugin(mongoose_delete, { deletedAt: true });

module.exports = mongoose.model('New', NewSchema);
