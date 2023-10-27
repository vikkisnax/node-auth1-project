const router = require('express').Router();
const bcrypt = require('bcryptjs');
const User = require('..//users/users-model');


// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength` middleware functions from `auth-middleware.js`. 
const {
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength
} = require('./auth-middleware')

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
router.post('/register', checkUsernameFree, checkPasswordLength, (req, res, next) => {
  // res.json('auth router register')
  //store user in db. get User model
  const { username, password } = req.body;
  //store the hash, not the plain text password
  const hash = bcrypt.hashSync(password, 8) // 2^8

  User.add({username, password: hash})
  .then(saved => {
    res.status(201).json(saved)
  })
  .catch(next)
})



/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */
router.post('/login', checkUsernameExists, (req, res, next) => {
  // res.json('auth router login')
  const { password } = req.body;
  //req.user.password bc req has a user which has the password in the db
  // bcrypt will compareSync the plaintext password to the hashed password in the db
  if (bcrypt.compareSync(password, req.user.password)){
    //if password is valid, make it so 1. the cookie is set on the client
    //header will travel w/ a response. 2. make it so server stores sesssion w/ session id corresponding to this user. cookie carries session id w/ it
    // change session object by storing user on session, we will do 1 and 2 above
    req.session.user = req.user
    res.json({
      message: `Welcome ${req.user.username}`
    })
  } else {
    next({
      status: 401,
      message: "Invalid credentials"
    })
  }
})



/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
router.get('/logout', (req, res, next) => {
  // res.json('auth router logout')
  //check if there's a session 
  if (req.session.user) {
    const { username } = req.session.user
    //destroy session
    req.session.destroy(err => {
      if (err) {
        res.json({ message: `You can never leave, ${username}...` })
      } else {
        // the following line is optional: compliant browsers will delete the cookie from their storage
        res.set('Set-Cookie', 'monkey=; SameSite=Strict; Path=/; Expires=Thu, 01 Jan 1970 00:00:00')
        
        res.json({ message: 'logged out' })
      }
    })
  } else {
    res.json({ message: 'no session' })
  }
})


// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;