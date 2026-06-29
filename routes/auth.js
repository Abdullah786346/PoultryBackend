const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const fs = require('fs');

const User = require('../models/User');

// Setup multer storage (local)
const uploadDir = process.env.UPLOAD_DIR || 'uploads';
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${Date.now()}-${Math.round(Math.random()*1e9)}${ext}`);
  }
});
const upload = multer({ storage });

// POST /api/auth/signup
router.post('/signup',
  upload.single('profilePicture'),
  // Validation
  [
    body('fullName').notEmpty(),
    body('email').isEmail(),
    body('password').isLength({ min: 6 }),
    body('membershipCategory').notEmpty()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const {
        fullName, gender, dob, email, phone, country, city,
        position, organization, qualification, specialization, membershipCategory
      } = req.body;

      // Check email exists
      const exists = await User.findOne({ email });
      if (exists) return res.status(400).json({ error: 'Email already registered' });

      // Hash password
      const passwordHash = await bcrypt.hash(req.body.password, 10);

      // Build profilePic URL if uploaded
      let profilePicUrl = '';
      if (req.file) {
        profilePicUrl = `${req.protocol}://${req.get('host')}/${uploadDir}/${req.file.filename}`;
      }

      const user = new User({
        fullName,
        profilePicUrl,
        gender,
        dob: dob ? new Date(dob) : undefined,
        email,
        phone,
        country,
        city,
        position,
        organization,
        qualification,
        specialization,
        membershipCategory,
        passwordHash
      });

      await user.save();

      // Don't return passwordHash
      const userObj = user.toObject();
      delete userObj.passwordHash;

      res.status(201).json({ message: 'User registered', user: userObj });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  }
);

module.exports = router;
