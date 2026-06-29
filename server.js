import express from "express";

import mongoose from "mongoose";

import multer from "multer";

import cors from "cors";

import dotenv from "dotenv";

import bcrypt from "bcryptjs";

import jwt from "jsonwebtoken";



dotenv.config();

const app = express();



// Middleware

app.use(cors({
  origin: process.env.FRONTEND_URL || "*",
  credentials: true
}));

app.use(express.json());

app.use(express.urlencoded({ extended: true }));

// Serve static files from uploads directory
app.use('/uploads', express.static('uploads'));



// File upload configuration

import { v2 as cloudinary } from "cloudinary";

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_API_KEY,
  api_secret: process.env.CLOUD_API_SECRET,
});

const storage = multer.memoryStorage();
const upload = multer({ storage });

// Helper function to upload buffer to Cloudinary
const uploadToCloudinary = (fileBuffer) => {
  return new Promise((resolve, reject) => {
    const uploadStream = cloudinary.uploader.upload_stream(
      { folder: "poultry" },
      (error, result) => {
        if (error) return reject(error);
        resolve(result);
      }
    );
    uploadStream.end(fileBuffer);
  });
};



// MongoDB connection

mongoose.connect(process.env.MONGO_URI)

  .then(() => console.log("MongoDB connected"))

  .catch(err => console.error("MongoDB connection error:", err));



// User schema

const userSchema = new mongoose.Schema({

  fullName: String,

  profilePicture: String,

  gender: String,

  dob: Date,

  email: { type: String, unique: true },

  phone: String,

  country: String,

  city: String,

  position: String,

  organization: String,

  qualification: String,

  specialization: String,

  membershipCategory: String,

  password: String,

  isVerified: { type: Boolean, default: false },

  role: { type: String, enum: ['admin', 'member'], default: 'member' },

  paymentStatus: { type: String, enum: ['unpaid', 'pending_approval', 'approved'], default: 'unpaid' },

  paymentDetails: {

    paymentMethod: { type: String, enum: ['card', 'jazzcash', 'bank_transfer'], default: 'card' },

    // Card payment fields
    cardNumber: String,

    cardHolder: String,

    expiryDate: String,

    cvv: String,

    // JazzCash payment fields
    jazzcashAccount: String,
    jazzcashMobile: String,
    jazzcashTransactionId: String,

    // Bank transfer fields
    bankAccountNumber: String,
    bankAccountHolder: String,
    bankName: String,

    // Common fields
    referenceNumber: String,

    amount: String,

    currency: String,

    paidAt: Date

  },

  createdAt: { type: Date, default: Date.now }

});



// Password hashing middleware

userSchema.pre("save", async function (next) {

  if (!this.isModified("password")) return next();

  const salt = await bcrypt.genSalt(10);

  this.password = await bcrypt.hash(this.password, salt);

  next();

});



// Password comparison method

userSchema.methods.matchPassword = async function (enteredPassword) {

  return await bcrypt.compare(enteredPassword, this.password);

};



const User = mongoose.model("User", userSchema);



// Signup endpoint (with logging & validation)

app.post("/api/signup", upload.single("profilePicture"), async (req, res) => {

  try {

    console.log("Received signup request");

    console.log("Body:", req.body);

    console.log("File:", req.file);



    const { password, confirmPassword, email, ...userData } = req.body;



    if (!password || !confirmPassword || password !== confirmPassword) {

      return res.status(400).json({ error: "Passwords do not match or are missing" });

    }

    if (!userData.dob) {

      return res.status(422).json({ error: "Date of birth is required" });

    }



    const userExists = await User.findOne({ email });

    if (userExists) {

      return res.status(409).json({ error: "Email already exists" });

    }



    const isFirstUser = (await User.countDocuments({})) === 0;

    const role = isFirstUser ? 'admin' : 'member';

    const paymentStatus = isFirstUser ? 'approved' : 'unpaid';

    let profilePictureUrl = "";
    if (req.file) {
      try {
        const uploadResult = await uploadToCloudinary(req.file.buffer);
        profilePictureUrl = uploadResult.secure_url;
      } catch (uploadError) {
        console.error("Cloudinary upload error:", uploadError);
        return res.status(500).json({ error: "Failed to upload profile picture to Cloudinary" });
      }
    }

    const newUser = new User({

      ...userData,

      email,

      password,

      profilePicture: profilePictureUrl,

      dob: new Date(userData.dob),

      isVerified: true, // Auto-verify for development

      role,

      paymentStatus

    });



    await newUser.save();

    console.log("User created:", newUser.email);



    const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, { expiresIn: "1h" });

    console.log(`Verification token: ${token}`);



    res.json({

      message: "Signup successful! Please check your email for verification.",

      userId: newUser._id

    });



  } catch (err) {

    console.error("Signup error:", err);

    if (err.code === 11000) {

      return res.status(409).json({ error: "Duplicate field value entered." });

    }

    res.status(500).json({ error: `Server error: ${err.message}` });

  }

});



// Login endpoint

app.post("/api/login", async (req, res) => {

  try {

    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user || !(await user.matchPassword(password))) {

      return res.status(401).json({ error: "Invalid credentials" });

    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

    res.json({

      token,

      user: {

        id: user._id,

        fullName: user.fullName,

        email: user.email,

        profilePicture: user.profilePicture,

        position: user.position,

        organization: user.organization,

        city: user.city,

        country: user.country,

        membershipCategory: user.membershipCategory,

        phone: user.phone,

        gender: user.gender,

        dob: user.dob,

        qualification: user.qualification,

        specialization: user.specialization,

        role: user.role,

        paymentStatus: user.paymentStatus,

        paymentDetails: user.paymentDetails

      }

    });

  } catch (err) {

    console.error("Login error:", err);

    res.status(500).json({ error: "Server error" });

  }

});



// Email verification endpoint

app.get("/api/verify-email", async (req, res) => {

  try {

    const { token } = req.query;

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    await User.findByIdAndUpdate(decoded.id, { isVerified: true });

    res.json({ message: "Email verified successfully!" });

  } catch (err) {

    console.error("Verification error:", err);

    res.status(400).json({ error: "Invalid or expired token" });

  }

});



// Forgot password endpoint
app.post("/api/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Generate reset token (valid for 1 hour)
    const resetToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    
    // For development, return the token directly
    // In production, you would send this via email
    res.json({
      message: "Password reset token generated",
      resetToken,
      // In production, you would send: "Please check your email for password reset instructions"
    });
  } catch (err) {
    console.error("Forgot password error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Reset password endpoint
app.post("/api/reset-password", async (req, res) => {
  try {
    const { token, newPassword, confirmPassword } = req.body;
    
    if (!newPassword || !confirmPassword || newPassword !== confirmPassword) {
      return res.status(400).json({ error: "Passwords do not match or are missing" });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Hash new password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    
    await user.save();
    
    res.json({ message: "Password reset successfully" });
  } catch (err) {
    console.error("Reset password error:", err);
    if (err.name === 'JsonWebTokenError') {
      return res.status(400).json({ error: "Invalid or expired token" });
    }
    res.status(500).json({ error: "Server error" });
  }
});



// Manual verification endpoint for development
app.post("/api/verify-user", async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOneAndUpdate({ email }, { isVerified: true }, { new: true });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json({ message: "User verified successfully", user });
  } catch (err) {
    console.error("Manual verification error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Forgot password endpoint
app.post("/api/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: "No user found with that email address" });
    }
    
    // Generate reset token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "15m" });
    const resetLink = `${req.protocol}://${req.get('host')}/reset-password?token=${token}`;
    console.log(`Password reset link generated for ${email}: ${resetLink}`);

    res.json({
      message: "Password reset link sent! Check your console or use the link below.",
      resetLink
    });
  } catch (err) {
    console.error("Forgot password error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Reset password endpoint
app.post("/api/reset-password", async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || !password) {
      return res.status(400).json({ error: "Token and new password are required" });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    user.password = password; // pre-save hook will hash it automatically
    await user.save();

    res.json({ message: "Password reset successfully!" });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(400).json({ error: "Invalid or expired reset token" });
  }
});



// Protected route example

app.get("/api/protected", async (req, res) => {

  try {

    const token = req.headers.authorization?.split(" ")[1];

    if (!token) return res.status(401).json({ error: "Not authorized" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await User.findById(decoded.id).select("-password");

    if (!user) return res.status(404).json({ error: "User not found" });

    res.json(user);

  } catch (err) {

    console.error("Protected route error:", err);

    res.status(401).json({ error: "Invalid token" });

  }

});



// Middleware for authentication and authorization

const authenticateUser = async (req, res, next) => {

  try {

    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {

      return res.status(401).json({ error: "Not authorized, token missing" });

    }

    const token = authHeader.split(" ")[1];

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await User.findById(decoded.id).select("-password");

    if (!user) {

      return res.status(404).json({ error: "User not found" });

    }

    req.user = user;

    next();

  } catch (err) {

    console.error("Auth middleware error:", err);

    return res.status(401).json({ error: "Not authorized, invalid token" });

  }

};



const adminOnly = (req, res, next) => {

  if (req.user && req.user.role === 'admin') {

    next();

  } else {

    return res.status(403).json({ error: "Forbidden, admin access only" });

  }

};



// POST /api/pay-fee - Submit mock payment details

app.post("/api/pay-fee", authenticateUser, async (req, res) => {

  try {

    const {
      paymentMethod,
      // Card fields
      cardNumber, cardHolder, expiryDate, cvv,
      // JazzCash fields
      jazzcashAccount, jazzcashMobile, jazzcashTransactionId,
      // Bank transfer fields
      bankAccountNumber, bankAccountHolder, bankName,
      // Common fields
      referenceNumber, amount, currency
    } = req.body;



    const user = await User.findById(req.user._id);

    if (!user) {

      return res.status(404).json({ error: "User not found" });

    }



    user.paymentStatus = 'pending_approval';



    if (paymentMethod === 'jazzcash') {

      if (!jazzcashAccount || !jazzcashMobile || !jazzcashTransactionId) {

        return res.status(400).json({ error: "JazzCash account, mobile number, and transaction ID are required." });

      }

      user.paymentDetails = {

        paymentMethod: 'jazzcash',

        jazzcashAccount,
        jazzcashMobile,
        jazzcashTransactionId,
        referenceNumber: referenceNumber || jazzcashTransactionId,

        amount: amount || (user.membershipCategory === 'student' ? '25' : '50'),

        currency: currency || 'USD',

        paidAt: new Date()

      };

    } else if (paymentMethod === 'bank_transfer') {

      if (!bankAccountNumber || !bankAccountHolder || !bankName || !referenceNumber) {

        return res.status(400).json({ error: "Bank account number, holder name, bank name, and reference number are required." });

      }

      user.paymentDetails = {

        paymentMethod: 'bank_transfer',

        bankAccountNumber,
        bankAccountHolder,
        bankName,
        referenceNumber,

        amount: amount || (user.membershipCategory === 'student' ? '25' : '50'),

        currency: currency || 'USD',

        paidAt: new Date()

      };

    } else {

      // Credit card default

      if (!cardNumber || !cardHolder || !expiryDate || !cvv) {

        return res.status(400).json({ error: "All card details are required" });

      }



      const cleanedCardNumber = cardNumber.replace(/\s+/g, '');

      const lastFour = cleanedCardNumber.slice(-4);

      const maskedCardNumber = `•••• •••• •••• ${lastFour}`;



      user.paymentDetails = {

        paymentMethod: 'card',

        cardNumber: maskedCardNumber,

        cardHolder,

        expiryDate,

        cvv: '•••', // do not store CVV

        amount: amount || (user.membershipCategory === 'student' ? '25' : '50'),

        currency: currency || 'USD',

        paidAt: new Date()

      };

    }



    await user.save();



    const userObj = user.toObject();

    delete userObj.password;



    res.json({

      message: "Payment details submitted successfully. Pending admin approval.",

      user: userObj

    });

  } catch (err) {

    console.error("Payment submission error:", err);

    res.status(500).json({ error: "Server error" });

  }

});



// GET /api/admin/users - Admin only: list all users

app.get("/api/admin/users", authenticateUser, adminOnly, async (req, res) => {

  try {

    const users = await User.find({}).select("-password").sort({ createdAt: -1 });

    res.json(users);

  } catch (err) {

    console.error("Admin list users error:", err);

    res.status(500).json({ error: "Server error" });

  }
});



// POST /api/admin/approve-payment - Admin only: approve user payment

app.post("/api/admin/approve-payment", authenticateUser, adminOnly, async (req, res) => {

  try {

    const { userId } = req.body;

    if (!userId) {

      return res.status(400).json({ error: "User ID is required" });

    }



    const user = await User.findById(userId);

    if (!user) {

      return res.status(404).json({ error: "User not found" });

    }



    user.paymentStatus = 'approved';

    await user.save();



    res.json({

      message: "Payment approved successfully",

      user: {

        id: user._id,

        email: user.email,

        paymentStatus: user.paymentStatus

      }

    });

  } catch (err) {

    console.error("Approve payment error:", err);

    res.status(500).json({ error: "Server error" });

  }

});



// POST /api/admin/reject-payment - Admin only: reject user payment

app.post("/api/admin/reject-payment", authenticateUser, adminOnly, async (req, res) => {

  try {

    const { userId } = req.body;

    if (!userId) {

      return res.status(400).json({ error: "User ID is required" });

    }



    const user = await User.findById(userId);

    if (!user) {

      return res.status(404).json({ error: "User not found" });

    }



    user.paymentStatus = 'unpaid';

    user.paymentDetails = undefined;

    await user.save();



    res.json({

      message: "Payment rejected/revoked. User payment status set back to unpaid.",

      user: {

        id: user._id,

        email: user.email,

        paymentStatus: user.paymentStatus

      }

    });

  } catch (err) {

    console.error("Reject payment error:", err);

    res.status(500).json({ error: "Server error" });

  }

});



// Global error handling middleware

app.use((err, req, res, next) => {

  console.error("Unhandled error:", err);

  res.status(err.statusCode || 500).json({ error: err.message || "Server error" });

});



// Start server
const PORT = process.env.PORT || 5000;
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Handle server errors
server.on('error', (err) => {
  console.error('Server error:', err);
  process.exit(1);
});

// Handle process termination
process.on('SIGINT', () => {
  console.log('Shutting down server...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

export default app;

