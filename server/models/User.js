const mongoose = require('mongoose')
const bcrypt = require('bcrypt');
const saltRounds = 10 //비밀번호 암호화할 때 사용하는 변수
const jwt = require('jsonwebtoken');

//유저 정보 모음
const userSchema = mongoose.Schema({
    name: {
        type : String,
        maxlength: 50
    },
    email: {
        type: String,
        trim: true,
        unique: 1
    },
    password: {
        type: String,
        minlength: 5
    },
    lastname: {
        type: String,
        maxlength: 50
    },
    role: {
        type: Number,
        default: 0
    },
    image: String,
    token: {
        type: String
    },
    tokenExp: {
        type: Number
    }
})

userSchema.pre('save', function( next ){
    var user = this; //유저 정보 접근을 위해서

    if(user.isModified('password')){ //비밀번호가 변경되는 경우
        // 비밀번호를 암호화 시킨다.
        bcrypt.genSalt(saltRounds, function(err,salt){
            if(err) return next(err)

            bcrypt.hash(user.password, salt, function(err,hash){
                if(err) return next(err)

                user.password = hash
            
                next() //다음으로 넘어가기
            })
        })
    } else {
        next() //다음으로 넘어가기
    }
})

userSchema.methods.comparePassword = function(plainPassword, cb) {
    // 입력된 비밀번호를 암호화해서 데이터베이스에 있는 비밀번호와 비교하기
    bcrypt.compare(plainPassword, this.password, function(err, isMatch) {
        if(err) return cb(err);
        cb(null, isMatch)
    })
}

userSchema.methods.generateToken = function(cb){
    var user = this;
    //console.log('user._id', user._id)

    //jsonwebtoken을 이용해서 token을 생성하기
    var token = jwt.sign(user._id.toHexString(),'secretToken')
    //만든 token을 user.token에 저장시키기
    user.token = token
    user.save(function(err, user){
        if(err) return cb(err)
        cb(null, user)
    })
}

userSchema.statics.findByToken = function(token, cb){
    var user = this;

    //토큰을 복호화한다.
    jwt.verify(token, 'secretToken', function(err, decoded) {
        // 유저 아이디를 이용해서 유저를 찾은 다음에
        // 클라이언트에서 가져온 토큰과 데이터 베이스에 보관된 토큰이 일치하는지 확인

        user.findOne({"_id":decoded,"token":token}, function(err,user) {
            if(err) return cb(err);
            cb(null,user)
        })
    })
}


const User = mongoose.model('User', userSchema)

module.exports = {User}