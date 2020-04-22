const express = require('express');
const router = express.Router();

const bcrypt = require('bcryptjs');
const passport = require('passport');

// User Model

const User = require('../models/Users');

//Login Page
router.get('/login', (req,res) => res.render('login'));

//Regiser Page
router.get('/register', (req,res) => res.render('register'));

// Register handle

router.post('/register', (req,res) => {
  const {name,email,password,password2} = req.body;

  let errors = [];

  //Check required fields

  if(!name || !email || !password || !password2)
    errors.push({ msg: 'Please fill all the fields.'});

  if(password != password2)
    errors.push({msg: 'Passwords do not match.'});

  // Check Password length

  if(password.length<6)
    errors.push({msg:'Password length should be greater than 6 characters'});

  if(errors.length>0) {
    res.render('register',{
      errors,
      name,
      email,
      password,
      password2
    });
    console.log(errors);
  }
  else {
    //Validation passed

    User.findOne({email: email})
      .then(user => {
          if(user) {

              //User exists
              errors.push({msg:'Email is already registered.'})
              res.render('register',{
                errors,
                name,
                email,
                password,
                password2
              });
          }
          else {
            const newUser = new User({
              name,
              email,
              password
            });

            //Hash Password
            bcrypt.genSalt(10, (err,salt) =>
              bcrypt.hash(newUser.password,salt, (err, hash) => {
                if(err) throw err;

                // Set password to hash
                newUser.password = hash;

                // Save user
                newUser.save()
                  .then(
                    user => {
                      req.flash('success_msg','You are now registered.');
                      res.redirect('/users/login');
                    }
                  )
                  .catch(console.log(err));
              }))

          }
        });

  }

});

// Login
router.post('/login', (req, res, next) => {
  passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/users/login',
    failureFlash: true
  })(req, res, next);
});

// Logout
router.get('/logout', (req, res) => {
  req.logout();
  req.flash('success_msg', 'You are logged out');
  res.redirect('/users/login');
});

module.exports = router;
