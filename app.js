var express = require('express'),
  routes = require('./routes'),
  http = require('http'),
  path = require('path'),
  mongoose = require('mongoose'),
  models = require('./models')
  dbUrl = process.env.MONGOHQ_URL || 'mongodb://@localhost:27017/blog',
  db = mongoose.connect(dbUrl, {safe: true});

// Dotenv for secret env variables
var dotenv = require('dotenv').load();

// Express.js Middleware
var session = require('express-session');
var RedisStore = require('connect-redis')(session);

if (process.env.REDISTOGO_URL) {
  var rtg   = require("url").parse(process.env.REDISTOGO_URL);
  var redis = require("redis").createClient(rtg.port, rtg.hostname);
  var redisAuth = redis.auth(rtg.auth.split(":")[1]);
} else {
  var redis = require("redis").createClient();
}

var logger = require('morgan'),
  cookieParser = require('cookie-parser'),
  bodyParser = require('body-parser'),
  methodOverride = require('method-override');

var errorHandler = require('errorhandler');
if (process.env.NODE_ENV === 'development') {
  app.use(errorHandler({
    dumpExceptions: true,
    showStack: true
  }));
} else if (process.env.NODE_ENV === 'production') {
  app.use(errorHandler());
}

var app = express();
app.locals.appTitle = 'sweet-blog';

// Expose collections to request handlers
app.use(function(req, res, next) {
  if (!models.Article || ! models.User) return next(new Error("No models."))
  req.models = models;
  return next();
});

// Express.js configs
app.set('port', process.env.PORT || 3000);
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

// Express middleware config
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded());
app.use(cookieParser(process.env.PARSER_SECRET));
// in production
app.use(session({ 
  store: new RedisStore({ 
    host: rtg.hostname, port: rtg.port, db: redisAuth[0], pass: redisAuth[1] }),
  secret: process.env.SESSION_SECRET
}));
// in development     
// app.use(session({ 
//  store: new RedisStore({
//    host: "127.0.0.1",
//    port: "6379",
//    db: 1 }),
//  secret: process.env.SESSION_SECRET
// }));
app.use(methodOverride());
app.use(require('stylus').middleware(__dirname + '/public'));
app.use(express.static(path.join(__dirname, 'public')));

// Authentication middleware
app.use(function(req, res, next) {
  if (req.session && req.session.admin)
    res.locals.admin = true;
  next();
});

// Authorizatioin
var authorize = function(req, res, next) {
  if (req.session && req.session.admin)
    return next();
  else
    return res.sendStatus(401);
};


// Pages/routes
app.get('/', routes.index);
app.get('/login', routes.user.login);
app.post('/login', routes.user.authenticate);
app.get('/logout', routes.user.logout);
app.get('/admin', authorize, routes.article.admin);
app.get('/post', authorize, routes.article.post);
app.post('/post', authorize, routes.article.postArticle);
app.get('/articles/:slug', routes.article.show);

// API routes
app.all('/api', authorize); // adds authorize to all api routes
app.get('/api/articles', routes.article.list);
app.post('/api/articles', routes.article.add);
app.put('/api/articles/:id', routes.article.edit);
app.del('/api/articles/:id', routes.article.delete);

app.all('*', function(req, res) {
  res.sendStatus(404);
})

var server = http.createServer(app);
var boot = function () {
  server.listen(app.get('port'), function(){
    console.info('Express server listening on port ' + app.get('port'));
  });
}
var shutdown = function() {
  server.close();
}
if (require.main === module) {
  boot();
} else {
  console.info('Running app as a module')
  exports.info = boot;
  exports.shutdown = shutdown;
  exports.port = app.get('port');
}