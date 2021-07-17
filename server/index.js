const express = require('express')
const app = express()
const port = 5000
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const config = require('./config/key');
const {auth} = require('./middleware/auth');
const {User} = require("./models/User");

//application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({extended: true}));
//application/json
app.use(bodyParser.json());
app.use(cookieParser());

//mongoDB와의 연결을 위해서
const mongoose = require('mongoose')
mongoose.connect(config.mongoURI, {
    useNewUrlParser:true, useUnifiedTopology:true,useCreateIndex: true, useFindAndModify:false
}).then(()=> console.log('MongoDB Connected...'))
  .catch(err=>console.log(err))

app.get('/', (req, res) => res.send('Hello World!'))

app.get('/api/hello', (req,res)=>{
  res.send("안녕하세요 !")
})

//유저 정보 등록시 이 부분 사용
app.post('/api/users/register', (req, res) => {

  //회원가입할 때 필요한 정보들을 client에서 가져오면
  //그것들을 데이터 베이스에 넣어준다.

    const user = new User(req.body)
    //이 사이에서 User.js에 있는 save메소드가 실행되고 결과에 따라 아래 조건문 분기됨
    user.save((err,userInfo)=>{
      if(err) return res.json({success: false, err})
      return res.status(200).json({
        success: true
      })
    })
})

//유저 로그인 시 이 부분 사용
app.post('/api/users/login', (req, res) => {

  //요청된 이메일을 데이터베이스에서 있는지 찾는다.
  User.findOne({email: req.body.email}, (err,user) => {
    if(!user) { //데이터베이스에 입력한 이메일이 없는 경우
      return res.json({
        loginSuccess: false,
        message: "제공된 이메일에 해당하는 유저가 없습니다."
      })
    }

    //요청된 이메일이 데이터 베이스에 있다면 비밀번호가 맞는 비밀번호인지 확인
    user.comparePassword(req.body.password,(err, isMatch)=>{
      if(!isMatch) //입력한 비밀번호가 맞지 않는 경우
        return res.json({loginSuccess: false, message: "비밀번호가 틀렸습니다."})

      //비밀번호까지 맞다면 토큰을 생성하기
      user.generateToken((err, user)=> {
        if(err) return res.status(400).send(err);

        //토큰을 저장한다. 어디에? 쿠키, 로컬스토리지 등등...
        res.cookie("x_auth",user.token) //여기서는 쿠키에 저장
        .status(200)
        .json({loginSuccess: true, userId: user._id})
      })
    })
  })
  
  // role이 0이 아니면 관리자
  app.get('/api/users/auth', auth , (req, res)=>{
    // 여기까지 미들웨어를 통과해 왔다는 얘기는 Authentication이 true라는 말
    res.status(200).json({
      _id: req.user._id,
      isAdmin: req.user.role === 0? false:true,
      isAuth: true,
      email: req.user.email,
      name: req.user.name,
      lastname: req.user.lastname,
      role: req.user.role,
      image: req.user.image
    })
  })
  
  app.get('/api/users/logout',auth,(req,res)=> {
    User.findOneAndUpdate({_id: req.user._id},
      {token: ""},
      (err,user) => {
        if(err) return res.json({success: false, err});
        return res.status(200).send({
          success: true
        })
      })
  })

})

app.listen(port, () => console.log(`Example app listening on port ${port}!`))