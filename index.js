const express = require('express')
const logger = require('morgan')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const jwt = require('jsonwebtoken')
const jwtSecret = require('crypto').randomBytes(16) // 16*8=256 random bits 
const cookieParser = require('cookie-parser')
const mongoose = require("mongoose");

const { ExtractJwt } = require('passport-jwt');
const JwtStrategy = require('passport-jwt').Strategy
const { loginUser } = require('./controllers/authController');
const User = require('./models/User');

const app = express()
const port = 3000

app.use(logger('dev'))
app.use(cookieParser())

mongoose.set("strictQuery", false);
const mongoDB = "mongodb+srv://aluma98:YO9aIr9ieS9tF05A@cluster0.cli1tam.mongodb.net/local_library?retryWrites=true&w=majority";

main().catch((err) => console.log(err));
async function main() {
  await mongoose.connect(mongoDB);
}

//AUTH STUFF-------------------------------------------------------------------------------------------------------------

passport.use('username-password', new LocalStrategy(
  {
    usernameField: 'username',  // it MUST match the name of the input field for the username in the login HTML formulary
    passwordField: 'password',  // it MUST match the name of the input field for the password in the login HTML formulary
    session: false // we will store a JWT in the cookie with all the required session data. Our server does not need to keep a session, it's going to be stateless
  },
  async (username, password, done) => {
    try {
      const user = await loginUser(username, password);
      if (user) {
        return done(null, user);  // Successful authentication
      } else {
        return done(null, false);  // Authentication failed
      }
    } catch (error) {
      return done(error);
    }
  }
))

passport.use('jwtCookie', new JwtStrategy(
    {
      jwtFromRequest: ExtractJwt.fromExtractors([
        (req) => {
          return req?.cookies?.jwt;  // Extract JWT from cookie
        }
      ]),
      secretOrKey: jwtSecret
    },
    async (jwtPayload, done) => {
      try {
        // Use the username from the JWT payload to find the user in the database
        const user = await User.findOne({ username: jwtPayload.sub }).exec();
  
        if (user) {
          // If user found, return the user object
          return done(null, user);
        } else {
          // If no user is found, return false
          return done(null, false);
        }
      } catch (error) {
        // In case of any error, return the error
        return done(error, false);
      }
    }
  ))

app.use(express.urlencoded({ extended: true })) // needed to retrieve html form fields (it's a requirement of the local strategy)
app.use(passport.initialize())  // we load the passport auth middleware to our express application. It should be loaded before any route.

//-------------------------------------------------------------------------------

app.get('/',  passport.authenticate(
    'jwtCookie',
    { session: false, failureRedirect: '/login' }
  ),
  (req, res) => {
    res.send(`Welcome to your private page, ${req.user.username}!`) // we can get the username from the req.user object provided by the jwtCookie strategy
  }
)


app.get('/login',
  (req, res) => {
    res.sendFile('login.html', { root: __dirname })
  }
)


app.post('/login', (req, res) => {
    const { username, password } = req.body;
    loginUser(username, password)
      .then(user => {
        if (!user) {
          return res.status(401).send('Authentication failed');
        }
        // Assuming `user` is the authenticated user object
        const jwtClaims = {
          sub: user.username,
          iss: 'localhost:3000',
          aud: 'localhost:3000',
          exp: Math.floor(Date.now() / 1000) + 604800, // 1 week from now
          role: 'user' // Example role
        };
  
        const token = jwt.sign(jwtClaims, jwtSecret);
        res.cookie('jwt', token, { httpOnly: true, secure: true });
        res.redirect('/');
      })
      .catch(error => {
        console.error('Login error:', error);
        res.status(500).send('Login error');
      });
  });


  app.get('/logout', (req, res) => {
    res.clearCookie('jwt'); // Clear the JWT cookie
    res.redirect('/login'); // Redirect to login page
  });


app.use(function (err, req, res, next) {
  console.error(err.stack)
  res.status(500).send('Something broke!')
})

app.listen(port, () => {
  console.log(`app running at http://localhost:${port}`)
})