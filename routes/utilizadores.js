var express = require('express');
var router = express.Router();
var mongojs = require('mongojs');
var db = mongojs('mongodb://alfa:alfa1963@ds159880.mlab.com:59880/bdviagens', ['utilizadores']);
// config/passport.js
var LocalStrategy   = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var configAuth = require('./auth');
var passport = require('passport');
var bcrypt   = require('bcrypt-nodejs');



var utilizador={
    Nome: String,
    Email: { type: String, required: true},
    Password: { type: String, required: true },
    Activo: { type: Boolean, default: true },
    Data: { type: Date, default: Date.now() },
    facebook: {
    id: String,
    token: String,
    email: String,
    name: String,
    username: String,
  },
};

/* GET ALL  /utilizadores */
router.get('/utilizadores', function (req, res, next) {
    db.utilizadores.find(function (err, utilizadores) {
        if (err) { res.send(err); }
        console.log('todos os utilizadores: ' + JSON.stringify(utilizadores));
        res.json(utilizadores);
    });
});

/* GET ONE   /utilizadores/id */
router.get('/utilizadores/:id', function (req, res, next) {
    db.utilizadores.findOne({ _id: mongojs.ObjectId(req.params.id) }, function (err, utilizador) {
        if (err) { res.send(err); }
        console.log('Utilizador id: ' + JSON.stringify(utilizador));
        res.json(utilizador);
    });
});

/* DELETE   /utilizadores/id */
router.delete('/utilizadores/:id', function (req, res, next) {
    db.utilizadores.remove({ _id: mongojs.ObjectId(req.params.id) }, function (err, utilizador) {
        if (err) { res.send(err); }
        console.log('Utilizador eliminado: ' + JSON.stringify(utilizador));
        res.json(utilizador);
    });
});

/* POST     /utilizadores */
router.post('/utilizadores', function (req, res) {
    utilizador = req.body;
    db.utilizadores.insert(utilizador, function (err, utilizador) {
        if (err) {
            res.send({ 'erro': 'Ocurreu um erro' });
        } else {
            console.log('Utilizador inserido: ' + JSON.stringify(utilizador));
            res.send(utilizador);
        }
    });
});

///generateHash
/*utilizador.methods.generateHash = function(password) {  
  return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
};
utilizador.methods.validPassword = function(password) {  
  return bcrypt.compareSync(password, this.local.password);
};*/

    // LOCAL LOGIN =============================================================
    passport.use('local-login', new LocalStrategy({
        usernameField : 'Email',
        passwordField : 'Password',
        passReqToCallback : true // allows us to pass back the entire request to the callback
    },
    function(req, email, password, done) { // callback with email and password from our form
        // find a user whose email is the same as the forms email
       db.utilizadores.findOne({ 'local.email' :  email }, function(err, user) {
            if (err)
                return done(err);
            if (!user)
                return done(null, false('loginMessage', 'No user found.')); 
            // if the user is found and password is wrong
            if (!user.validPassword(password))
                return done(null, false( 'Oops! Wrong password.')); 
            // return successful user
            return done(null, user);
        });

    }));

    // FACEBOOK ================================================================
    passport.use(new FacebookStrategy({
        // pull in our app id and secret from our auth.js file
        clientID        : configAuth.facebookAuth.clientID,
        clientSecret    : configAuth.facebookAuth.clientSecret,
        callbackURL     : configAuth.facebookAuth.callbackURL

    },
    // facebook will send back the token and profile
    function(token, refreshToken, profile, done) {
        // asynchronous
        process.nextTick(function() {
            // find the user in the database based on their facebook id
          db.utilizadores.findOne({ 'facebook.id' : profile.id }, function(err, user) {
                if (err)
                    return done(err);
                // if the user is found, then log them in
                if (user) {
                    return done(null, user); // user found, return that user
                } else {
                    // if there is no user found with that facebook id, create them
                    var newUser  = new User();
                    // set all of the facebook information in our user model
                    newUser.facebook.id    = profile.id; // set the users facebook id                   
                    newUser.facebook.token = token; // we will save the token that facebook provides to the user                    
                    newUser.facebook.name  = profile.name.givenName + ' ' + profile.name.familyName; // look at the passport user profile to see how names are returned
                    newUser.facebook.email = profile.emails[0].value; // facebook can return multiple emails so we'll take the first
                    // save our user to the database
                    newUser.save(function(err) {
                        if (err)
                            throw err;
                        // if successful, return the new user
                        return done(null, newUser);
                    });
                }

            });
        });
    }));

//
 module.exports = router;
