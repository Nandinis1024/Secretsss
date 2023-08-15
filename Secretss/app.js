//jshint esversion:6
require('dotenv').config();
const express = require("express");
const mongoose = require("mongoose");
//const https = require("https");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate')

const port = 3000;

const app = express();

app.use(bodyParser.urlencoded({extended: true}));
app.set("view engine", "ejs");
app.use(express.static("public"));

app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
  }))

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb://127.0.0.1:27017/secretsDB', {useNewUrlParser: true});

const secretsSchema = new mongoose.Schema ({
    username: String,
    password: String,
    googleId: String
})

secretsSchema.plugin(passportLocalMongoose);
secretsSchema.plugin(findOrCreate);

const Secret = mongoose.model("Secret", secretsSchema);

passport.use(Secret.createStrategy());

// used to serialize the user for the session
passport.serializeUser(function(user, done) {
    done(null, user.id); 
   // where is this user.id going? Are we supposed to access this anywhere?
});

// used to deserialize the user
passport.deserializeUser(async function(id, done) {
    try {
      let user = await Secret.findById(id);
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  });
  


passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    Secret.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", async (req, res) => {
    res.render("home");
})

app.get('/auth/google',
  passport.authenticate('google', { scope: ['email','profile'] }));

  app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    res.redirect('/secret');
  }
);


app.get("/secrets", async (req, res)=>{
    if(req.isAuthenticated()){
        res.render("secrets");

    }
    else {
        res.redirect("/login");

    }
   
})


app.get("/register", async (req, res)=>{
    res.render("register");
})


app.post("/register", async (req, res) =>{
    try{
        const user = new Secret({username: req.body.username});
        await user.setPassword(req.body.password);
        await user.save();
        await Secret.authenticate()('user', 'password');
            res.redirect("/secrets");
        }
    catch (err){
        console.log(err);
    }

})


app.get("/login", async (req, res)=>{
    res.render("login");
})

app.post("/login", async (req, res)=>{
    const newUser = new Secret({
        username: req.body.username,
        password: req.body.password
    });

   req.login(newUser, (err)=>{
    if(err){
        console.log(err)
    }
    else{
        passport.authenticate("local")(req, res, ()=>{
            res.redirect("/secrets");
        })
    }

    });
})



app.get("/submit", async (req, res)=>{
    res.render("submit");
})

app.get("/logout", async( req, res)=>{
    req.logout(()=>{
        res.redirect("/");

    });
    
})






app.listen(port, async ()=>{
    console.log(`http://localhost:${port}`);
})


