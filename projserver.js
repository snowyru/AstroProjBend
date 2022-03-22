// import the express function
const express = require('express'); // == const express = require('./node_modules/express/index');

// import and run dotenv
require('dotenv').config();


//const { append } = require('express/lib/response');

// import body-parser to read POST request
const bodyParser = require('body-parser');

// import cors for cross-origin resource charing
const cors = require('cors');    // cross over resource sharing

// import express-form data
const expressFormData = require('express-form-data');



// import cloudinary for images
const cloudinary = require('cloudinary').v2;

cloudinary.config(
    {
        cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
        api_key: process.env.CLOUDINARY_API_KEY,
        api_secret: process.env.CLOUDINARY_API_SECRET,
    }
)



// import mongoose to connect to mongoDB by using javascript
const mongoose = require('mongoose');

//const UserModel = require('./models/UserModel.js');

const userRoutes = require('./routes/user-route.js')

const productRoutes = require('./routes/product-routes.js')












// ------------ ---------------------------------- ------------
// ------------ start of passportjs  configuration ------------
// ------------ ---------------------------------- ------------

// Use passport, passport-jwt to read the client jwt
const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const jwtSecret = process.env.JWT_SECRET;

const passportJwtOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: jwtSecret,
}

// This function will tell passport how what to do
// with the payload.
const passportJwt = (passport) => {
    passport.use(
        new JwtStrategy(
            passportJwtOptions,
            (jwtPayload, done) => {

                // Tell passport what to do with payload
                UserModel
                .findOne({ _id: jwtPayload._id })
                .then(
                    (dbDocument) => {
                        // The done() function will pass the 
                        // dbDocument to Express. The user's 
                        // document can then be access via req.user
                        return done(null, dbDocument)
                    }
                )
                .catch(
                    (err) => {
                        // If the _id or anything is invalid,
                        // pass 'null' to Express.
                        if(err) {
                            console.log(err);
                        }
                        return done(null, null)
                    }
                )

            }
        )
    )
};
passportJwt(passport)




















const { options } = require('nodemon/lib/config');

// creTE SERVER OBJECT BY CALLING EXPRESS
const projserver = express();

// Configure express for reading body for POST requests
projserver.use(bodyParser.urlencoded({ extended: false }));

// Configure express for JSON as well
projserver.use(bodyParser.json());



// configure express for cors
projserver.use(cors());


// Configure express for Express Form Data
projserver.use( expressFormData.parse() );


// connect to mongoDB
const connectionString = process.env.MONGODB_CONNECTION_STRING;
const connectionConfig = {
    'useNewUrlParser' : true,
    'useUnifiedTopology' : true
};

mongoose
.connect(connectionString,connectionConfig) // returns a promis like (if the connection is true (then) will work)
.then(
    function() {
        console.log('DB is connected')
    }
)
.catch(
    function() {
        console.log('DB error',dbError)   // the dberror will come from mongoose 
    }
);


// creating get route
projserver.get('/',
    //'/home',                    //  http://localhost:3001/home this is the document of the server
                        
    function(req,res) {
        res.send("Finally thank god");
    }
);


projserver.use(
    '/user',userRoutes
)


projserver.use (
    '/product',productRoutes
)

projserver.listen(
    process.env.PORT,
    function() {
        console.log(`server is running on http://localhost:${process.env.PORTi}`)
    }
);


