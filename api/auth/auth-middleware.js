const User = require('../users/users-model')

/*
  If the user does not have a session saved in the server

  status 401
  {
    "message": "You shall not pass!"
  }
*/
// do last
function restricted(req, res, next) {
  //console.log('restricted mw');
  //if there's a user on the session, then we're good - user logged in successfully. only works if client sends proper cookie back so server can find the session 
  if (req.session.user){
    next()
  } else{
    next({
      status: 401,
      message: "You shall not pass!"
    })
  }
  //now we need a client who will automatically send the cookie back on subsequent request to the same api/website
}



/*
  If the username in req.body already exists in the database

  status 422
  {
    "message": "Username taken"
  }
*/
//returns a promise so async await
async function checkUsernameFree(req, res, next) {
  try{
    const users = await User.findBy({ username: req.body.username})

    if (!users.length){
      next()
    } else {
      next({
        status: 422,
        message: "Username taken"
      })
    }
  } catch(err){
    next(err)
  }
}

/*
  If the username in req.body does NOT exist in the database

  status 401
  {
    "message": "Invalid credentials"
  }
*/
//we want login usernamme to be there
//async await bc want model function to rreturn info/promise first
async function checkUsernameExists(req, res, next) {
  try{
    const users = await User.findBy({ username: req.body.username})

    if (users.length){
      //add user to req object. get the first user in the array
      req.user = users[0]
      next()
    } else {
      next({
        status: 401,
        message: "Invalid credentials"
      })
    }
  } catch(err){
    next(err)
  }
}

/*
  If password is missing from req.body, or if it's 3 chars or shorter

  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
*/
//for resigtering new users
//dont need db from model so no need async
function checkPasswordLength(req, res, next) {
  if(!req.body.password || req.body.password.length < 3) {
    next({
      status: 422,
      message: "Password must be longer than 3 chars"
    })
  } else {
    next()
  }
}

// Don't forget to add these to the `exports` object so they can be required in other modules
module.exports = {
  restricted,
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength
}