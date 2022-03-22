// Reference:
// For mongoose methods, see
// https://mongoosejs.com/docs/api/model.html
const mongoose = require('mongoose');
const express = require('express');
const router = express.Router();
const UserModel = require('../modules/UserModel.js');
const bcryptjs = require('bcryptjs');
const cloudinary = require('cloudinary').v2;
const jwt = require('jsonwebtoken');
const jwtSecret = process.env.JWT_SECRET;


router.post('/register',               // http://localhost:3001/user/
    async function(req, res) {
        
        // Read the body of POST request
        const document = {
            "firstName": req.body.firstName,
            "lastName": req.body.lastName,
            "email": req.body.email,
            "password": req.body.password,
            "phone": req.body.phone
        }

        // Start of BcryptJS

        // Check if account exists
        UserModel
        .findOne( {email: document.email} )
        .then(
            async function(dbDocument) {

                
                if (dbDocument) {
                    // Reject account creation
                    res.status(403).json(
                        {
                            "status": "not ok",
                            "message": "Account already exists"
                        }
                    );
                }
                else {
                    /* UPLOAD FILE TO CLOUDINARY */
                    // Check if file has been attached
                    const files = Object.values(req.files);
                    if(files.length > 0) {
                        // Upload the file to Cloudinary
                        await cloudinary.uploader.upload(
                            files[0].path,
                            function(cloudinaryErr, cloudinaryResult) {

                                // If upload is succesful
                                if(!cloudinaryErr) {
                                    // Add image url to 'document'
                                    document['avatar'] = cloudinaryResult.url;
                                }
                                // else
                                else {
                                    // Send client error
                                    res.json(
                                        {
                                            message: "Avatar upload error in /user/register"
                                        }
                                    )
                                }
                            }
                        )
                    };

                    // 1. Generate salt
                    bcryptjs.genSalt(
                        function(bcryptError, theSalt) {
                        // 2. Add salt and password ----> hash

                            bcryptjs.hash(
                                document.password,
                                theSalt,
                                function(hashError, theHash) {
                                    // Replace the password with theHash
                                    document.password = theHash;

                                    /* CREATE DOCUMENT IN MONGODB */
                                    // Create a new document in database
                                    UserModel
                                    .create(document)
                                    // If successful
                                    .then(
                                        function(dbDocument) {
                                            res.json(
                                                {
                                                    document: dbDocument,
                                                    message: "User created"
                                                }
                                            );
                                        }
                                    )
                                    // Otherwise
                                    .catch(
                                        function(dbError) {
                                            console.log('DB user create error', dbError);
                                            res.json(
                                                {
                                                    message: "User create error"
                                                }
                                            );
                                        }
                                    ); 
                                }
                            )
                        }
                    )
                }
            }
        )
        .catch(
            function(dbError) {
                console.log('Error /user/register', dbError);
                res.status(503).json(
                    {
                        "status": "not ok",
                        "message": "MongoDB error"
                    }
                );
            }
        );
        // End of BcryptJS
    }
);

// Login user
router.post('/login', 
    (req, res) => {

        // Capture form data
        const formData = {
            email: req.body.email,
            password: req.body.password,
        }

        // Check if email exists
        UserModel
        .findOne({ email: formData.email })
        .then(
            (dbDocument) => {
                // If email exists
                if(dbDocument) {
                    // Compare the password sent againt password in database
                    bcryptjs.compare(
                        formData.password,          // password user sent
                        dbDocument.password         // password in database
                    )
                    .then(
                        (isMatch) => {
                            // If passwords match...
                            if(isMatch) {
                                // Generate the Payload
                                const payload = {
                                    _id: dbDocument._id,
                                    email: dbDocument.email
                                }
                                // Generate the jsonwebtoken
                                jwt
                                .sign(
                                    payload,
                                    jwtSecret,
                                    (err, jsonwebtoken) => {
                                        if(err) {
                                            console.log(err);
                                            res.status(501).json(
                                                {
                                                    "message": "Something went wrong"
                                                }
                                            );
                                        }
                                        else {
                                            // Send the jsonwebtoken to the client
                                            res.json(
                                                {
                                                    "message": {
                                                        email: dbDocument.email,
                                                        avatar: dbDocument.avatar,
                                                        firstName: dbDocument.firstName,
                                                        lastName: dbDocument.lastName,
                                                        jsonwebtoken: jsonwebtoken
                                                    }
                                                }
                                            );
                                        }
                                    }
                                )
                            }
                            // If passwords don't match, reject login
                            else {
                                res.status(401).json(
                                    {
                                        "message": "Wrong email or password"
                                    }
                                );
                            }
                        }
                    )
                    .catch(
                        (err) => {
                            console.log(err)
                        }
                    )
                }
                // If email does not exist
                else {
                    // reject the login
                    res.status(401).json(
                        {
                            "message": "Wrong email or password"
                        }
                    );
                }
            }
        )
        .catch(
            (err) => {
                console.log(err);

                res.status(503).json(
                    {
                        "status": "not ok",
                        "message": "Please try again later"
                    }
                );
            }
        )
    }
)


router.get('/all',                          // http://localhost:3001/user/
    function(req, res) {

        UserModel
        .find(
            // {
            //     _id: {
            //         $lt: mongoose.Types.ObjectId("621e4259978683f4dfdb91e2")
            //     }
            // }
        )
        .then(
            function(document) {
                res.send(document)
            }
        )
        .catch(
            function(dbError) {
                console.log('Error /user/all', dbError)
            }
        );

    }
);

router.put('/update',
    function(req, res) {

        // The search criteria
        const search = {_id: mongoose.Types.ObjectId(req.body._id)}

        // The replacement of the document
        const updatedDocument = {
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            email: req.body.email,
            password: req.body.password,
            phone: req.body.phone
        }

        // This will tell MongoDB to show the updated document
        const options = {new: true}

        UserModel
        .findOneAndUpdate(
            search,
            updatedDocument,
            options
        )
        .then(
            function(updatedDocument) {
                res.send(updatedDocument);
            }
        )
        .catch(
            function(error) {
                console.log('Error /user/update', error);
            }
        )
    }
);


module.exports = router;




















// // Reference:
// // For mongoose methods, see
// // https://mongoosejs.com/docs/api/model.html
// const mongoose = require('mongoose');
// const express = require('express');
// const router = express.Router();
// const UserModel = require('../modules/UserModel.js');//models/UserModel.js
// const bcryptjs = require('bcryptjs');
// const cloudinary = require('cloudinary').v2;
// const jwt = require('jsonwebtoken');
// const jwtSecret = process.env.JWT_SECRET;


// router.post('/register',               // http://localhost:3001/user/
//     async function(req, res) {
        
//         // Read the body of POST request
//         const document = {
//             "firstName": req.body.firstName,
//             "lastName": req.body.lastName,
//             "email": req.body.email,
//             "password": req.body.password,
//             "phone": req.body.phone
//         }

//         // Start of BcryptJS

//         // Check if account exists
//         UserModel
//         .findOne( {email: document.email} )
//         .then(
//             async function(dbDocument) {

                
//                 if (dbDocument) {
//                     // Reject account creation
//                     res.status(403).json(
//                         {
//                             "status": "not ok",
//                             "message": "Account already exists"
//                         }
//                     );
//                 }
//                 else {
//                     /* UPLOAD FILE TO CLOUDINARY */
//                     // Check if file has been attached
//                     const files = Object.values(req.files);
//                     if(files.length > 0) {
//                         // Upload the file to Cloudinary
//                         await cloudinary.uploader.upload(
//                             files[0].path,
//                             function(cloudinaryErr, cloudinaryResult) {

//                                 // If upload is succesful
//                                 if(!cloudinaryErr) {
//                                     // Add image url to 'document'
//                                     document['avatar'] = cloudinaryResult.url;
//                                 }
//                                 // else
//                                 else {
//                                     // Send client error
//                                     res.json(
//                                         {
//                                             message: "Avatar upload error in /user/register"
//                                         }
//                                     )
//                                 }
//                             }
//                         )
//                     };

//                     // 1. Generate salt
//                     bcryptjs.genSalt(
//                         function(bcryptError, theSalt) {
//                         // 2. Add salt and password ----> hash

//                             bcryptjs.hash(
//                                 document.password,
//                                 theSalt,
//                                 function(hashError, theHash) {
//                                     // Replace the password with theHash
//                                     document.password = theHash;

//                                     /* CREATE DOCUMENT IN MONGODB */
//                                     // Create a new document in database
//                                     UserModel
//                                     .create(document)
//                                     // If successful
//                                     .then(
//                                         function(dbDocument) {
//                                             res.json(
//                                                 {
//                                                     document: dbDocument,
//                                                     message: "User created"
//                                                 }
//                                             );
//                                         }
//                                     )
//                                     // Otherwise
//                                     .catch(
//                                         function(dbError) {
//                                             console.log('DB user create error', dbError);
//                                             res.json(
//                                                 {
//                                                     message: "User create error"
//                                                 }
//                                             );
//                                         }
//                                     ); 
//                                 }
//                             )
//                         }
//                     )
//                 }
//             }
//         )
//         .catch(
//             function(dbError) {
//                 console.log('Error /user/register', dbError);
//                 res.status(503).json(
//                     {
//                         "status": "not ok",
//                         "message": "MongoDB error"
//                     }
//                 );
//             }
//         );
//         // End of BcryptJS
//     }
// );

// // Login user
// router.post('/login', 
//     (req, res) => {

//         // Capture form data
//         const formData = {
//             email: req.body.email,
//             password: req.body.password,
//         }

//         // Check if email exists
//         UserModel
//         .findOne({ email: formData.email })
//         .then(
//             (dbDocument) => {
//                 // If email exists
//                 if(dbDocument) {
//                     // Compare the password sent againt password in database
//                     bcryptjs.compare(
//                         formData.password,          // password user sent
//                         dbDocument.password         // password in database
//                     )
//                     .then(
//                         (isMatch) => {
//                             // If passwords match...
//                             if(isMatch) {
//                                 // Generate the Payload
//                                 const payload = {
//                                     _id: dbDocument._id,
//                                     email: dbDocument.email
//                                 }
//                                 // Generate the jsonwebtoken
//                                 jwt
//                                 .sign(
//                                     payload,
//                                     jwtSecret,
//                                     (err, jsonwebtoken) => {
//                                         if(err) {
//                                             console.log(err);
//                                             res.status(501).json(
//                                                 {
//                                                     "message": "Something went wrong"
//                                                 }
//                                             );
//                                         }
//                                         else {
//                                             // Send the jsonwebtoken to the client
//                                             res.json(
//                                                 {
//                                                     "message": {
//                                                         email: dbDocument.email,
//                                                         avatar: dbDocument.avatar,
//                                                         firstName: dbDocument.firstName,
//                                                         lastName: dbDocument.lastName,
//                                                         jsonwebtoken: jsonwebtoken
//                                                     }
//                                                 }
//                                             );
//                                         }
//                                     }
//                                 )
//                             }
//                             // If passwords don't match, reject login
//                             else {
//                                 res.status(401).json(
//                                     {
//                                         "message": "Wrong email or password"
//                                     }
//                                 );
//                             }
//                         }
//                     )
//                     .catch(
//                         (err) => {
//                             console.log(err)
//                         }
//                     )
//                 }
//                 // If email does not exist
//                 else {
//                     // reject the login
//                     res.status(401).json(
//                         {
//                             "message": "Wrong email or password"
//                         }
//                     );
//                 }
//             }
//         )
//         .catch(
//             (err) => {
//                 console.log(err);

//                 res.status(503).json(
//                     {
//                         "status": "not ok",
//                         "message": "Please try again later"
//                     }
//                 );
//             }
//         )
//     }
// )


// router.get('/all',                          // http://localhost:3001/user/
//     function(req, res) {

//         UserModel
//         .find(
//             // {
//             //     _id: {
//             //         $lt: mongoose.Types.ObjectId("621e4259978683f4dfdb91e2")
//             //     }
//             // }
//         )
//         .then(
//             function(document) {
//                 res.send(document)
//             }
//         )
//         .catch(
//             function(dbError) {
//                 console.log('Error /user/all', dbError)
//             }
//         );

//     }
// );

// router.put('/update',
//     function(req, res) {

//         // The search criteria
//         const search = {_id: mongoose.Types.ObjectId(req.body._id)}

//         // The replacement of the document
//         const updatedDocument = {
//             firstName: req.body.firstName,
//             lastName: req.body.lastName,
//             email: req.body.email,
//             password: req.body.password,
//             phone: req.body.phone
//         }

//         // This will tell MongoDB to show the updated document
//         const options = {new: true}

//         UserModel
//         .findOneAndUpdate(
//             search,
//             updatedDocument,
//             options
//         )
//         .then(
//             function(updatedDocument) {
//                 res.send(updatedDocument);
//             }
//         )
//         .catch(
//             function(error) {
//                 console.log('Error /user/update', error);
//             }
//         )
//     }
// );


// module.exports = router;






















// const express = require('express');
// const mongoose = require('mongoose')
// const router = express.Router();
// const UserModel = require('../modules/UserModel.js'); //please confirm input to your dir
// const cloudinary = require('cloudinary').v2;

// //I'm not too confident in the backend so please confirm this works with the server.js thank you :)

// router.post('/register',               
//     function(req, res) {
        
//         // Read the body of POST request
//         const document = {
//             "firstName": req.body.firstName,
//             "lastName": req.body.lastName,
//             "country": req.body.country,
//             "region": req.body.region,
//             "bio": req.body.bio,
//             "email": req.body.email,
//             "password": req.body.password,
//         }

//             //Avatar code Begin------------------------------------------------------------------------------------------------------

//         //Check if file has been attached
//         const files = Object.values(req.files);
//         if(files.length > 0) {

//         //upload the file to cloudinary
//         cloudinary.uploader.upload(
//             files[0].path,
//             function(cloudinaryErr, cloudinaryResult) {
//              //if upload is succesful
//                 if(!cloudinaryErr) {
//                 //Add image to url to 'document' 
//                 document['avatar'] = cloudinaryResult.url;    
//                 }
//                 else{
//                     //client error
//                     res.json(
//                         {
//                             message: "Avatar upload error in /user/register"
//                         }
//                     )
//                 }

//             }
//         )
            

//         }

//         // Create a new document in database
//         UserModel
//         .create(document)
//         // If successful
//         .then(
//             function(dbDocument) {
//                 res.json(
//                     {
//                         document: dbDocument,
//                         message: "User created"
//                     }
//                 );
//             }
//         )
//         // Otherwise
//         .catch(
//             function(dbError) {
//                 console.log('DB user create error', dbError)
//             }
//         );        
//     }
// );

//     //Fetching all the users code -----------------------------------------------------------------------------------------------

// router.get('/all',                          
//     function(req, res) {

//         UserModel
//         .find()
//         .then(
//             function(document) {
//                 res.send(document)
//             }
//         )
//         .catch(
//             function(dbError) {
//                 console.log('Error /user/all', dbError)
//             }
//         );

//     }
// );

//     //Updating the user profile code -----------------------------------------------------------------------------------------------

// router.put('/update',
//     function(req, res) {

//         // The search criteria
//         const search = {_id: mongoose.Types.ObjectId(req.body._id)}

//         // The replacement of the document
//         const updatedDocument = {
//             "firstName": req.body.firstName,
//             "lastName": req.body.lastName,
//             "country": req.body.country,
//             "region": req.body.region,
//             "bio": req.body.bio,
//             "email": req.body.email,
//             "password": req.body.password,
//         }

//         // This will tell MongoDB to show the updated document
//         const options = {new: true}

//         UserModel
//         .findOneAndUpdate(
//             search,
//             updatedDocument,
//             options
//         )
//         .then(
//             function(updatedDocument) {
//                 res.send(updatedDocument);
//             }
//         )
//         .catch(
//             function(error) {
//                 console.log('Error /user/update', error);
//             }
//         )
//     }
// );


// module.exports = router;