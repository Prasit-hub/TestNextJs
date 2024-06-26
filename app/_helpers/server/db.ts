import mongoose from 'mongoose';

const Schema = mongoose.Schema;
const uri = 'mongodb+srv://medpark-it-dev:jkAadybFiSrfhVVG@cluster-mp.t59sq9e.mongodb.net'

mongoose.connect(uri!);
mongoose.Promise = global.Promise;

export const db = {
    User: userModel()
};

// mongoose models with schema definitions

function userModel() {
    const schema = new Schema({
        username: { type: String, unique: true, required: true },
        hash: { type: String, required: true },
        firstName: { type: String, required: true },
        lastName: { type: String, required: true }
    }, {
        // add createdAt and updatedAt timestamps
        timestamps: true
    });

    schema.set('toJSON', {
        virtuals: true,
        versionKey: false,
        transform: function (doc, ret) {
            delete ret._id;
            delete ret.hash;
        }
    });

    return mongoose.models.User || mongoose.model('User', schema);
}
