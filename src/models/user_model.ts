import mongoose from 'mongoose'

const userSchema = new mongoose.Schema({
    email:{
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    fullname:{
        type:String,
        required:true
    },
    imageURL:{
        type:String,
        required:false
    },
    refresh_tokens:{
        type: [String]
    }
})

export = mongoose.model('User',userSchema)

