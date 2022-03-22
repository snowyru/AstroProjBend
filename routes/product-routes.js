const express = require("express");
const mongoose = require("mongoose");
const router = express.Router();
const ProductModel = require("../modules/ProductModel.js");
const cloudinary = require("cloudinary").v2;

// Add product
router.post(
  "/addProduct", // http://www.localhost:3000/product/addProduct
  async function (req, res) {
    const document = {
      name: req.body.name,
      price: req.body.price,
      category: req.body.category,
      description: req.body.description,
    };
    /* UPLOAD FILE TO CLOUDINARY */
    // Check if file has been attached
    const files = Object.values(req.files);
    if (files.length > 0) {
      // Upload the file to Cloudinary
      await cloudinary.uploader.upload(
        files[0].path,
        function (cloudinaryErr, cloudinaryResult) {
          // If upload is succesful
          if (!cloudinaryErr) {
            // Add image url to 'document'
            document["image"] = cloudinaryResult.url;
          }
          // else
          else {
            // Send client error
            res.json({
              message: "Avatar upload error in /user/register",
            });
          }
        }
      );
    }
    ProductModel.create(document)
      .then(function (dbDocument) {
        res.json({
          document: dbDocument,
          message: "Product Added",
        });
      })
      .catch(function (dbError) {
        console.log("DB product added error", dbError);
        res.json({
          message: "Product added error",
        });
      });
  }
);
// Get all products
router.get(
  "/all", // http://localhost:3001/user/
  function (req, res) {
    ProductModel.find()
      .then(function (document) {
        res.send(document);
      })
      .catch(function (dbError) {
        console.log("Error /user/all", dbError);
      });
  }
);

// Update product by ID
router.put("/update", function (req, res) {
  // The search criteria
  const search = { _id: mongoose.Types.ObjectId(req.body._id) };

  // The replacement of the document
  const updatedDocument = {
    name: req.body.name,
    price: req.body.price,
    category: req.body.category,
    description: req.body.description,
  };

  // This will tell MongoDB to show the updated document
  const options = { new: true };

  ProductModel.findOneAndUpdate(search, updatedDocument, options)
    .then(function (updatedDocument) {
      res.send(updatedDocument);
    })
    .catch(function (error) {
      console.log("Error /product/update", error);
    });
});

// @desc    Delete a product
// @route   DELETE /api/products/:id
// @access  Private/User
router.delete("/delete", async function (req, res) {
  // The search criteria
  const search = { _id: mongoose.Types.ObjectId(req.body._id) };
  // Find the product by ID
  ProductModel.findByIdAndDelete(search)
    .then(function () {
      res.send("product removed");
    })
    .catch(function (error) {
      console.log("Error /product/deleted", error);
    });
});

// const deleteProduct = asyncHandler(async (req, res) => {
//   const product = await Product.findById(req.params.id)

//   if (product) {
//     await product.remove()
//     res.json({ message: 'Product removed' })
//   } else {
//     res.status(404)
//     throw new Error('Product not found')
//   }
// })
module.exports = router;
