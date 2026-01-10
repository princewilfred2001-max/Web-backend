 // server.js
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

// Import your security config
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

// ==================== SCHEMAS ====================
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

userSchema.pre('save', function(next) { this.updatedAt = Date.now(); next(); });
userSchema.virtual('isLocked').get(function() { return !!(this.lockUntil && this.lockUntil > Date.now()); });

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
    } catch (err) { done(err, null); }
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
    } catch (err) { done(err, null); }
  }));
}

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id).select('-password -emailVerificationToken -passwordResetToken');
    done(null, user);
  } catch (err) { done(err, null); }
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

// ==================== PASSWORD RESET ====================
// Request reset link
app.post('/api/auth/request-password-reset', authLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'Email not found' });

    const resetToken = randomBytes(32).toString('hex');
    const hashedToken = createHash('sha256').update(resetToken).digest('hex');

    user.passwordResetToken = hashedToken;
    user.passwordResetExpires = Date.now() + 60*60*1000; // 1 hour
    await user.save();

    await sendPasswordResetEmail(user, resetToken);
    res.json({ message: 'Password reset email sent' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during password reset request' });
  }
});

// Reset password
app.post('/api/auth/reset-password/:token', authLimiter, async (req, res) => {
  try {
    const hashedToken = createHash('sha256').update(req.params.token).digest('hex');
    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) return res.status(400).json({ message: 'Invalid or expired reset token' });

    const { password } = req.body;
    if (!password || password.length < 8) return res.status(400).json({ message: 'Password must be at least 8 characters' });

    user.password = await bcrypt.hash(password, 12);
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    res.json({ message: 'Password reset successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during password reset' });
  }
});

// ==================== PROTECTED ROUTES EXAMPLE ====================
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password -emailVerificationToken -passwordResetToken');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching profile' });
  }
});

// ==================== SECURITY HARDENING ====================
// Apply strict limiter to sensitive endpoints
app.use('/api/auth/signup', authLimiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/request-password-reset', authLimiter);

// Detect suspicious input
app.use((req, res, next) => {
  const suspicious = Object.values(req.body || {}).some(value => detectSuspiciousInput(value));
  if (suspicious) {
    logSecurityEvent('SUSPICIOUS_INPUT_DETECTED', { path: req.path, body: req.body }, req);
    return res.status(400).json({ message: 'Suspicious input detected' });
  }
  next();
});

// Extra security headers
app.use(additionalSecurityHeaders);

// Rate limit for general API routes already applied: apiLimiter

// ==================== AUTH ROUTES ====================
app.use('/api/', apiLimiter);

app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Signup
app.post('/api/auth/signup', authLimiter, signupValidation, validate, async (req, res) => {
  try {
    const { firstName, lastName, username, email, password } = req.body;
    if ([firstName, lastName, username, email].some(i => detectSuspiciousInput(i))) {
      logSecurityEvent('SUSPICIOUS_INPUT', { email }, req);
      return res.status(400).json({ message: 'Invalid input detected' });
    }
    if (await User.findOne({ email })) return res.status(400).json({ message: 'Email already registered' });

    const hashed = await bcrypt.hash(password, 12);
    const verificationToken = randomBytes(32).toString('hex');
    const hashedToken = createHash('sha256').update(verificationToken).digest('hex');

    const user = await User.create({
      firstName, lastName, username: username || firstName, email,
      password: hashed, emailVerificationToken: hashedToken,
      emailVerificationExpires: Date.now() + 24*60*60*1000, provider: 'local'
    });

    await sendVerificationEmail(user, verificationToken);
    res.status(201).json({ message: 'Account created, verify email!', email: user.email });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ message: 'Server error during signup' });
  }
});

// Email verification
app.get('/api/auth/verify-email/:token', async (req,res)=>{
  try{
    const hashed = createHash('sha256').update(req.params.token).digest('hex');
    const user = await User.findOne({ emailVerificationToken: hashed, emailVerificationExpires: { $gt: Date.now() } });
    if(!user) return res.status(400).json({ message: 'Invalid/expired token' });
    user.isEmailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpires = undefined;
    await user.save();
    const token = jwt.sign({ userId: user._id, email: user.email }, process.env.JWT_SECRET || 'secret', { expiresIn:'7d' });
    res.json({ message:'Email verified!', token, user:{id:user._id, email:user.email, firstName:user.firstName, lastName:user.lastName, isEmailVerified:user.isEmailVerified} });
  } catch(err){console.error(err); res.status(500).json({ message:'Server error' });}
});

// Login
app.post('/api/auth/login', authLimiter, loginValidation, validate, async (req,res)=>{
  try{
    const { email,password } = req.body;
    const user = await User.findOne({ email });
    if(!user) return res.status(401).json({ message:'Invalid email or password' });
    if(!user.isEmailVerified && user.provider==='local') return res.status(403).json({ message:'Email not verified' });
    const isValid = await bcrypt.compare(password,user.password);
    if(!isValid){ await user.incLoginAttempts(req.ip); return res.status(401).json({ message:'Invalid email or password' }); }
    if(user.loginAttempts>0) await user.resetLoginAttempts();
    user.lastLogin=Date.now(); user.lastLoginIP=req.ip; await user.save();
    const token = jwt.sign({ userId:user._id,email:user.email }, process.env.JWT_SECRET || 'secret',{expiresIn:'7d'});
    res.json({ message:'Login successful', token, user:{id:user._id, firstName:user.firstName,lastName:user.lastName,email:user.email} });
  }catch(err){console.error(err); res.status(500).json({ message:'Server error during login' });}
});

// ==================== OAUTH ENDPOINTS ====================
app.get('/api/auth/google', passport.authenticate('google',{ scope:['profile','email'] }));
app.get('/api/auth/google/callback', passport.authenticate('google',{ failureRedirect:'/login.html' }),(req,res)=>{
  const token=jwt.sign({ userId:req.user._id,email:req.user.email }, process.env.JWT_SECRET||'secret',{expiresIn:'7d'});
  res.redirect(`${process.env.FRONTEND_URL||'http://localhost:3000'}/dashboard.html?token=${token}`);
});

app.get('/api/auth/yahoo', passport.authenticate('yahoo',{ scope:['profile','email'] }));
app.get('/api/auth/yahoo/callback', passport.authenticate('yahoo',{ failureRedirect:'/login.html' }),(req,res)=>{
  const token=jwt.sign({ userId:req.user._id,email:req.user.email }, process.env.JWT_SECRET||'secret',{expiresIn:'7d'});
  res.redirect(`${process.env.FRONTEND_URL||'http://localhost:3000'}/dashboard.html?token=${token}`);
});

// ==================== START SERVER ====================
const PORT = process.env.PORT || 5000;
app.listen(PORT, ()=>console.log(`🚀 Server running on port ${PORT}`));
