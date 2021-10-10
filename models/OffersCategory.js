const mongoose = require("mongoose");
const Joi = require("joi");

const OffersCategorySchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true,
  },
  views: {
    type: Number,
    default: 0,
  },
  subCategory: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Domain",
    },
  ],
});

const validateOffer = (offer) => {
  const schema = {
    name: Joi.string().min(3).max(50).required(),
    subCategory: Joi.array().items(Joi.string().required()),
  };
  return Joi.validate(offer, schema);
};

const OffersCategory = mongoose.model("OffersCategory", OffersCategorySchema);

module.exports = { OffersCategory, validateOffer };
