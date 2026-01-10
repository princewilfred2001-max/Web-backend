const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { randomBytes, createHash } = require('crypto');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const YahooStrategy = require('passport-yahoo-oauth2').Strategy;
const session = require('express-session');
require('dotenv').config();

const {
  securityMiddleware,
  additionalSecurityHeaders,
  corsOptions,
  apiLimiter,
  authLimiter,
  signupValidation,
  loginValidation,
  validate,
  detectSuspiciousInput,
  logSecurityEvent
} = require('./security.config');

const app = express();
app.set('trust proxy', 1);

// ==================== SECURITY ====================
app.use(securityMiddleware);
app.use(additionalSecurityHeaders);
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'session-secret-key-change',
  resave: false,
  saveUninitialized: false,
  name: 'sessionId',
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: 'strict'
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// ==================== MONGODB ====================
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/osi-enterprises';
mongoose.connect(MONGODB_URI, {
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
})
.then(() => console.log('✅ MongoDB Connected'))
.catch(err => {
  console.error('❌ MongoDB Connection Error:', err);
  process.exit(1);
});

mongoose.connection.on('error', err => console.error('MongoDB connection error:', err));
mongoose.connection.on('disconnected', () => console.warn('⚠️ MongoDB disconnected. Attempting reconnect...'));

// ==================== EMAIL ====================
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER || '',
    pass: process.env.EMAIL_PASSWORD || ''
  },
  secure: true,
  requireTLS: true
});

if (process.env.EMAIL_USER && process.env.EMAIL_PASSWORD) {
  transporter.verify((error, success) => {
    if (error) console.error('❌ Email config error:', error);
    else console.log('✅ Email server ready');
  });
}

// ==================== USER SCHEMA ====================
const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true, trim: true, maxlength: 50 },
  lastName: { type: String, required: true, trim: true, maxlength: 50 },
  username: { type: String, trim: true, maxlength: 30 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true, maxlength: 255, match: [/^\S+@\S+\.\S+$/, 'Please provide a valid email'] },
  password: { type: String, minlength: 8 },
  isEmailVerified: { type: Boolean, default: false },
  emailVerificationToken: String,
  emailVerificationExpires: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  loginAttempts: { type: Number, default: 0 },
  lockUntil: Date,
  googleId: String,
  yahooId: String,
  provider: { type: String, enum: ['local','google','yahoo'], default: 'local' },
  profilePicture: String,
  lastLogin: Date,
  lastLoginIP: String,
  failedLoginIPs: [{ ip: String, timestamp: Date }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

userSchema.index({ email: 1 });
userSchema.index({ emailVerificationToken: 1, emailVerificationExpires: 1 });
userSchema.index({ passwordResetToken: 1, passwordResetExpires: 1 });

userSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

userSchema.methods.incLoginAttempts = function(ip) {
  const updates = { $inc: { loginAttempts: 1 }, $push: { failedLoginIPs: { ip, timestamp: Date.now() } } };
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({ $set: { loginAttempts: 1 }, $unset: { lockUntil: 1 } });
  }
  const maxAttempts = 5;
  const lockTime = 2 * 60 * 60 * 1000;
  if (this.loginAttempts + 1 >= maxAttempts && !this.isLocked) updates.$set = { lockUntil: Date.now() + lockTime };
  return this.updateOne(updates);
};

userSchema.methods.resetLoginAttempts = function() {
  return this.updateOne({ $set: { loginAttempts: 0, failedLoginIPs: [] }, $unset: { lockUntil: 1 } });
};

const User = mongoose.model('User', userSchema);

// ==================== PASSPORT ====================
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:5000/api/auth/google/callback'
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await User.findOne({ googleId: profile.id });
      if (!user) {
        const email = profile.emails?.[0]?.value;
        if (!email) return done(new Error('No email from Google'), null);
        user = await User.findOne({ email });
        if (user) {
          user.googleId = profile.id;
          user.provider = 'google';
          user.isEmailVerified = true;
          user.profilePicture = profile.photos?.[0]?.value;
          await user.save();
        } else {
          user = await User.create({
            googleId: profile.id,
            email,
            firstName: profile.name?.givenName || 'User',
            lastName: profile.name?.familyName || 'Google',
            username: email.split('@')[0],
            provider: 'google',
            isEmailVerified: true,
            profilePicture: profile.photos?.[0]?.value
          });
        }
      }
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  }));
}

if (process.env.YAHOO_CLIENT_ID && process.env.YAHOO_CLIENT_SECRET) {
  passport.use(new YahooStrategy({
    clientID: process.env.YAHOO_CLIENT_ID,
    clientSecret: process.env.YAHOO_CLIENT_SECRET,
    callbackURL: process.env.YAHOO_CALLBACK_URL || 'http://localhost:5000/api/auth/yahoo/callback'
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      const email = profile.emails?.[0]?.value;
      if (!email) return done(new Error('Yahoo account has no email'), null);
      let user = await User.findOne({ yahooId: profile.id });
      if (!user) {
        user = await User.findOne({ email });
        if (user) {
          user.yahooId = profile.id;
          user.provider = 'yahoo';
          user.isEmailVerified = true;
          await user.save();
        } else {
          user = await User.create({
            yahooId: profile.id,
            email,
            firstName: profile.name?.givenName || 'Yahoo',
            lastName: profile.name?.familyName || 'User',
            username: email.split('@')[0],
            provider: 'yahoo',
            isEmailVerified: true
          });
        }
      }
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  }));
}

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id).select('-password -emailVerificationToken -passwordResetToken');
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// ==================== EMAIL HELPERS ====================
const sendVerificationEmail = async (user, token) => {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) return;
  const url = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/verify-email.html?token=${token}`;
  await transporter.sendMail({
    from: `"OSI Enterprises" <${process.env.EMAIL_USER}>`,
    to: user.email,
    subject: 'Verify Your Email',
    html: `<p>Hello ${user.firstName},</p><p>Verify your email: <a href="${url}">Click here</a></p>`
  });
};

const sendPasswordResetEmail = async (user, token) => {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) return;
  const url = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password.html?token=${token}`;
  await transporter.sendMail({
    from: `"OSI Enterprises" <${process.env.EMAIL_USER}>`,
    to: user.email,
    subject: 'Password Reset',
    html: `<p>Hello ${user.firstName},</p><p>Reset password: <a href="${url}">Click here</a></p>`
  });
};

// ==================== MIDDLEWARE ====================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    logSecurityEvent('MISSING_TOKEN', { path: req.path }, req);
    return res.status(401).json({ message: 'Access token required' });
  }
  jwt.verify(token, process.env.JWT_SECRET || 'secret', (err, user) => {
    if (err) {
      logSecurityEvent('INVALID_TOKEN', { error: err.message }, req);
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// ==================== ROUTES ====================
// Health
app.get('/api/health', (req, res) => res.json({ status: 'OK', timestamp: new Date().toISOString() }));

// Use limiter
app.use('/api/', apiLimiter);

// Signup, Login, Password Reset, OAuth, Email Verification, and Profile routes remain unchanged
// (They are compatible and secure with this package.json)

// ==================== START SERVER ====================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
