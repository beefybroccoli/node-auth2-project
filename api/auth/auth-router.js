const router = require("express").Router();
const { checkUsernameExists, validateRoleName, checkUsernameFree, checkPassword, comparePassword, generateToken } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const {add} = require("../users/users-model");

router.post("/register", checkUsernameFree, validateRoleName, checkPassword, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  try{
    const{username, password, role_name} = req.body;
    const array = await add({username, password, role_name});
    res.status(201).json(array[0]);
  }catch(err){
    next(err);
  }
});


router.post("/login", checkUsernameExists, comparePassword, generateToken, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
    
    try{
      res.status(200).json({message:`${req.existingUser.username} is back!`, token:req.signedToken})
    }catch(err){
      next(err);
    }

});

module.exports = router;
