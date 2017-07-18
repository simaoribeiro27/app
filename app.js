var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var jsonfile = require('jsonfile');
//

//
//file up
var formData = require("express-form-data");
var multer = require('multer');
var upload = multer({ dest: './public/images/' });
var upload = multer({ storage: storage });
var storage = multer.memoryStorage();
var upload = multer().single('avatar');


var index = require('./routes/index');
var home = require('./routes/home');
var utilizadores = require('./routes/utilizadores');
var viagens = require('./routes/viagens');
var momentos = require('./routes/momentos');
var classificacoes= require('./routes/classificacoes');
//
var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', index);
app.use('/', home);
app.use('/', utilizadores);
app.use('/', viagens);
app.use('/', momentos);
app.use('/', classificacoes);
//


// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
