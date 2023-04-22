// routes/auth.routes.js

const { Router } = require('express');
const router = new Router();

const bcryptjs = require('bcryptjs');
const saltRounds = 10;

const User = require('../models/User.model');

// GET route ==> to display the signup form to users
router.get('/signup', (req, res) => res.render('auth/signup'));

// POST route ==> to process form data
router.post('/signup', (req, res, next) => {
   // console.log("The form data: ", req.body);

   const { username, email, password } = req.body;

   bcryptjs
      .genSalt(saltRounds)
      .then((salt) => bcryptjs.hash(password, salt))
      .then((hashedPassword) => {
         return User.create({
            // username: username
            username,
            email,
            // passwordHash => this is the key from the User model
            //     ^
            //     |            |--> this is placeholder (how we named returning value from the previous method (.hash()))
            passwordHash: hashedPassword,
         });
      })
      .then((userFromDB) => {
         // console.log("Newly created user is: ", userFromDB);
         res.redirect('/userProfile');
      })
      .catch((error) => next(error));
});

router.get('/userProfile', (req, res) => {
   res.render('users/user-profile', { userInSession: req.session.currentUser });
});
// GET route ==> to display the login form to users
router.get('/login', (req, res) => res.render('auth/login'));

// POST login route ==> to process form data
router.post('/login', (req, res, next) => {
   console.log('SESSION =====> ', req.session);
   const { email, password } = req.body;

   if (email === '' || password === '') {
      res.render('auth/login', {
         errorMessage: 'Please enter both, email and password to login.',
      });
      return;
   }

   User.findOne({ email })
      .then((user) => {
         if (!user) {
            res.render('auth/login', {
               errorMessage: 'Email is not registered. Try with other email.',
            });
            return;
         } else if (bcryptjs.compareSync(password, user.passwordHash)) {
            req.session.currentUser = user;
            res.redirect('/userProfile');
         } else {
            res.render('auth/login', { errorMessage: 'Incorrect password.' });
         }
      })
      .catch((error) => next(error));
});

router.post('/logout', (req, res, next) => {
   req.session.destroy((err) => {
      if (err) next(err);
      res.redirect('/');
   });
});

module.exports = router;
