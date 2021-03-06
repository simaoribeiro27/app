var express = require('express');
var router = express.Router();
//
var passport = require('passport');

/* GET home page. */
/*router.get('/', function(req, res, next) {
 res.render('./index');
});*/

//routes
router.get('/', function(req, res, next) {
  res.render('./index');
});

router.get('/login', function(req, res, next) {
  res.render('login.ejs');
});

router.get('/signup', function(req, res) {
   res.render('signup.ejs');
});

router.get('./profile', isLoggedIn, function(req, res) {
  res.render('profile.ejs', { user: req.user });
});

router.get('./logout', function(req, res) {
  req.logout();
  res.redirect('/');
});

router.post('./signup', passport.authenticate('local-signup', {
  successRedirect: './profile',
  failureRedirect: './signup',
  failureFlash: true,
}));

router.post('./login', passport.authenticate('local-login', {
  successRedirect: './profile',
  failureRedirect: './login',
  failureFlash: true,
}));

router.get('/auth/facebook', passport.authenticate('facebook', { scope: 'email' }));

router.get('/auth/facebook/callback', passport.authenticate('facebook', {
  successRedirect: './profile',
  failureRedirect: '/',
}));


module.exports = router;

function isLoggedIn(req, res, next) {
  if (req.isAuthenticated())
      return next();
  res.redirect('/');
}

