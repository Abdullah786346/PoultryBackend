const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  profilePicUrl: { type: String, default: '' },
  gender: { type: String },
  dob: { type: Date },
  email: { type: String, required: true, unique: true },
  phone: { type: String },
  country: { type: String },
  city: { type: String },
  position: { type: String },
  organization: { type: String },
  qualification: { type: String },
  specialization: { type: String },
  membershipCategory: { type: String },
  passwordHash: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', userSchema);
