const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const usersRouter = require('./users/users-router');
const authRouter = require('./auth/auth-router');
//authentication: session and cookies
//install npm i connect-session-knex so we can persist sessions in the db
const session = require('express-session');
//req this library and invoke it with the session
const Store = require('connect-session-knex')(session)
//need knex wrapper for store
const knex = require('../data/db-config')

/**
  Do what needs to be done to support sessions with the `express-session` package!
  To respect users' privacy, do NOT send them a cookie unless they log in.
  This is achieved by setting 'saveUninitialized' to false <-, 
  and by not changing the `req.session` object unless the user authenticates.

  Users that do authenticate should have a session persisted on the server,
  and a cookie set on the client. The name of the COOKIE should be "chocolatechip".

  The session can be persisted in memory (would not be adequate for production)
  or you can use a session store like `connect-session-knex` <-.
 */

const server = express();
//authentication: session and cookies
//configuration obj
const sessionConfig = {
  name: 'chocolatechip',
  secret: 'keep it secret, keep it safe!',
  cookie: { //configure the cookie
    maxAge: 1000 * 60 * 60, // =10 min. or else it dies when tab closes
    secure: false, // if true, the cookie is not set (/browswer won't send cookie) unless it's an https connection
    httpOnly: true, // if true the cookie is not accessible through document.cookie = secure -- / if false,  js on page can read cookie = not as secure
    // sameSite: 'none' // to enable 3rd party cookies but only with https
  },
  rolling: true,
  resave: false, // some data stores need this set to true
  saveUninitialized: false, // privacy implications, if false no cookie is set on client unless the req.session is changed
  store: new Store({ //takes its own config obj to store sessions
    knex, // configured instance of knex. knex wrapper
    tablename: 'sessions', // table that will store sessions inside the db, name it anything you want
    sidfieldname: 'sid', // column that will hold the session id, name it anything you want
    createtable: true, // if the table does not exist, it will create it automatically
    clearInterval: 1000 * 60 * 10, // time it takes to check for old sessions and remove them from the database to keep it clean and performant
  }),
}

//authentication: session and cookies
//invoke the configuration obj
server.use(session(sessionConfig))


server.use(helmet());
server.use(express.json());
server.use(cors());

//Routes
server.use('/api/users', usersRouter);
server.use('/api/auth', authRouter);





server.get("/", (req, res) => {
  res.json({ api: "up from server.js" });
});

server.use('*', (req, res, next) => {
  next({ status: 404, message: 'Not found!' })
})

//error handling mw
server.use((err, req, res, next) => { // eslint-disable-line
  res.status(err.status || 500).json({
    message: err.message,
    stack: err.stack,
  });
});

module.exports = server;
