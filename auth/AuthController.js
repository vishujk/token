var express = require('express');
var router = express.Router();
var bodyParser = require('body-parser');
router.use(bodyParser.urlencoded({ extended: false }));
router.use(bodyParser.json());
var User = require('../user/User');
var jwt = require('jsonwebtoken');
var bcrypt = require('bcryptjs');
var config = require('../config');
var VerifyToken = require('./VerifyToken');

router.post('/register', function(req, res) {
    //User.findOne({ email: req.body.email }, function (err, user) {
     // if (err) return res.status(500).send({message:'Error on the server.'});
      //if (!user) return res.status(401).send({message:'No user found.'});
      
      // if(user.email===req.body.email)
      // {
      //   return res.status(402).send({message:'Email id - '+user.email+' already register.'});
      // }
    
      var hashedPassword = bcrypt.hashSync(req.body.password, 8);

      User.create({
        name : req.body.name,
        email : req.body.email,
        password : hashedPassword
      },
      function (err, user) {
        if (err) return res.status(500).send({message:"There was a problem registering the user."})
        // create a token
         var token = jwt.sign({ id: user._id }, config.secret, {
           expiresIn: 86400 // expires in 24 hours
         });
        res.status(200).send({ auth: true, token: token });
        //res.status(200).send({ register: true ,message:"User Registered"});
      }); 
   // });
  });

  router.get('/me', function(req, res) {
    var token = req.headers['x-access-token'];
    if (!token) return res.status(401).send({ auth: false, message: 'No token provided.' });
    
    jwt.verify(token, config.secret, function(err, decoded) {
      if (err) return res.status(500).send({ auth: false, message: 'Failed to authenticate token.'  });
      
      //res.status(200).send(decoded);
      User.findById(decoded.id, function (err, user) {
        if (err) return res.status(500).send({message:"There was a problem finding the user."});
        if (!user) return res.status(404).send({message:"No user found."});
        
        res.status(200).send({ _id: user._id,name:user.name,email:user.email,auth: true });
      });
    });
  });

  router.get('/verifytoken', VerifyToken, function(req, res, next) {
    User.findById(req.userId, { password: 0 }, function (err, user) {
      if (err) return res.status(500).send({message:"There was a problem finding the user."});
      if (!user) return res.status(404).send({message:"No user found."});
      res.status(200).send({ _id: user._id,name:user.name,email:user.email,auth: true });
    });
  });

  router.post('/login', function(req, res) {
    User.findOne({ email: req.body.email }, function (err, user) {
      if (err) return res.status(500).send({message:'Error on the server.'});
      if (!user) return res.status(404).send({message:'No user found.'});
      var passwordIsValid = bcrypt.compareSync(req.body.password, user.password);
      if (!passwordIsValid) return res.status(401).send({ auth: false, token: null });
     
      var token = jwt.sign({ id: user._id }, config.secret, {
        expiresIn: 86400 // expires in 24 hours
      });
      res.status(200).send({ auth: true, token: token });
    });
  });

  // add this to the bottom of AuthController.js
module.exports = router;