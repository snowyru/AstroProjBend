const mongoose = require("mongoose");

// Product Schema
const ProductSchema = new mongoose.Schema(
  {
    // user: {
    //   type: mongoose.Schema.Types.ObjectId,
    //   required: true,
    //   ref: 'User',
    // },
    name: {
      type: String,
      required: true,
    },
    image: {
      type: String,
      required: true,
    },
    category: {
      type: String,
      required: true,
    },
    description: {
      type: String,
      required: true,
    },
    price: {
      type: Number,
      required: false,
      default: 0,
    },
    dateCreated: {
        type: Date,
        required: true,
        default: Date.now,
      },
  },
  // {
  //   timestamps: true,
  // }
)

// Create the model
const ProductModel = mongoose.model('product', ProductSchema);

// Export the model
module.exports = ProductModel;