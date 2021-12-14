const { JWT_SECRET } = require("../secrets/index"); // use this secret!
const {findBy} = require("../users/users-model");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");

const restricted = (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
    if (!req.headers.authorization){  
      res.status(401).json({"message": "Token required"});
    }else{
      const token = req.headers.authorization;
      jwt.verify(token, 'shh', (err , decoded)=>{
        if(err){
          res.status(401).json({"message": "Token invalid"});
        }else{
          req.decodedToken = decoded;
          console.log(" req.decodedToken = ", req.decodedToken);
          next();
        }
      })
    }

    
}

const only = role_name => (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
    if (req.decodedToken.role_name !== role_name){
      res.status(403).json({"message": "This is not for you"});
    }else{
      next();
    }
}

const checkUsernameFree = async (req, res, next) => {

  const {username} = req.body;
  if (typeof username === 'undefined'){
    res.status(401).json({"message": `require username`});
  }else{
      const array = await findBy({'username':username});
      if (array.length === 0){
          next();
      }else{
          res.status(401).json({"message": `username ${username} already taken`});
      }
  }
    
}

const checkPassword = async (req, res, next) => {
  const {password} = req.body;
  if (typeof password === 'undefined' || typeof password !== 'string' || password === ''){
    res.status(401).json({message:'require password'});
  }else{
    req.body.password =  bcrypt.hashSync(password, 10);
    next();
  }
}

const comparePassword = async (req, res, next) => {
  if ( !bcrypt.compareSync(req.body.password, req.existingUser.password)){
    res.status(401).json({"message": "Invalid credentials"});
  }else{
    next();
  }
}

const generateToken = async (req, res, next) => {

    const payload = {
      subject: req.existingUser.user_id,
      username: req.existingUser.username,
      role_name: req.existingUser.role_name,
    };

    const options = {
      expiresIn: '1d',
    }

    // req.signedToken = jwt.sign(payload, JWT_SECRET, options);
    req.signedToken = jwt.sign(payload, 'shh', options);
    next()
}

const checkUsernameExists = async (req, res, next) => {
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
    const array = await findBy({'username':req.body.username});
    if (array.length === 0){
      res.status(401).json({"message": "Invalid credentials"});
    }else{
      req.existingUser = array[0];
      next();
    }
}

const validateRoleName = (req, res, next) => {
  const {role_name} = req.body;
  /*
    If role_name is missing from req.body, or if after trimming it is just an empty string, set req.role_name to be 'student' and allow the request to proceed.
  */
  if (typeof role_name === 'undefined' || typeof role_name !== 'string' || role_name.trim() === ""){
    req.body.role_name = 'student';
    next();
  }
  /*
    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }
  */
  else if(role_name.trim() === 'admin'){
    res.status(422).json({"message": "Role name can not be admin"});
  }
  /*
    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
  else if(role_name.trim().length > 32){
    res.status(422).json({"message": "Role name can not be longer than 32 chars"});
  }
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.
  */
  else{
    req.body.role_name = role_name.trim();
    next();
  }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
  checkUsernameFree,
  checkPassword,
  comparePassword,
  generateToken
}
