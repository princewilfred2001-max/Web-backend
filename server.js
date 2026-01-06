const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
  origin: '*',
  credentials: true
}));
app.use(express.json());

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://your-connection-string';
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-change-in-production';

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('✅ MongoDB Connected'))
.catch(err => console.error('❌ MongoDB Connection Error:', err));

// ==================== MODELS ====================

// User Model
const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Project Model
const projectSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['website', 'app'], required: true },
  description: { type: String, default: '' },
  currency: { type: String, default: 'USD' },
  features: { type: String, default: '' },
  designStyle: { type: String, default: '' },
  webpages: { type: String, default: '' },
  appSize: { type: String, default: '' },
  phone: { type: String, default: '' },
  email: { type: String, default: '' },
  status: { type: String, enum: ['pending', 'active', 'completed'], default: 'pending' },
  paymentRef: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now }
});

const Project = mongoose.model('Project', projectSchema);

// Payment Model
const paymentSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  projectId: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
  reference: { type: String, required: true, unique: true },
  amount: { type: Number, default: 0 },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});

const Payment = mongoose.model('Payment', paymentSchema);

// ==================== MIDDLEWARE ====================

// Auth Middleware
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid or expired token' });
  }
};

// ==================== ROUTES ====================

// Health Check
app.get('/', (req, res) => {
  res.json({ 
    status: 'online',
    service: 'OSI Enterprises API',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

// ==================== AUTH ROUTES ====================

// Sign Up
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;

    // Validation
    if (!firstName || !lastName || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already registered' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword
    });

    await user.save();

    // Generate token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: 'Server error during signup' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// Get User Profile
app.get('/api/auth/profile', authMiddleware, async (req, res) => {
  try {
    res.json({
      user: {
        id: req.user._id,
        firstName: req.user.firstName,
        lastName: req.user.lastName,
        email: req.user.email
      }
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ message: 'Server error fetching profile' });
  }
});

// ==================== PROJECT ROUTES ====================

// Create Project
app.post('/api/projects/create', authMiddleware, async (req, res) => {
  try {
    const {
      type,
      description,
      currency,
      features,
      designStyle,
      webpages,
      appSize,
      phone,
      email
    } = req.body;

    if (!type) {
      return res.status(400).json({ message: 'Project type is required' });
    }

    const project = new Project({
      userId: req.user._id,
      type,
      description: description || '',
      currency: currency || 'USD',
      features: features || '',
      designStyle: designStyle || '',
      webpages: webpages || '',
      appSize: appSize || '',
      phone: phone || '',
      email: email || req.user.email,
      status: 'pending'
    });

    await project.save();

    res.status(201).json({
      message: 'Project created successfully',
      project: {
        id: project._id,
        type: project.type,
        status: project.status,
        createdAt: project.createdAt
      }
    });
  } catch (error) {
    console.error('Create project error:', error);
    res.status(500).json({ message: 'Server error creating project' });
  }
});

// Get All Projects for User
app.get('/api/projects/all', authMiddleware, async (req, res) => {
  try {
    const projects = await Project.find({ userId: req.user._id })
      .sort({ createdAt: -1 });

    res.json(projects.map(p => ({
      id: p._id,
      type: p.type,
      description: p.description,
      status: p.status,
      createdAt: p.createdAt
    })));
  } catch (error) {
    console.error('Get projects error:', error);
    res.status(500).json({ message: 'Server error fetching projects' });
  }
});

// Get Single Project
app.get('/api/projects/:id', authMiddleware, async (req, res) => {
  try {
    const project = await Project.findOne({
      _id: req.params.id,
      userId: req.user._id
    });

    if (!project) {
      return res.status(404).json({ message: 'Project not found' });
    }

    res.json(project);
  } catch (error) {
    console.error('Get project error:', error);
    res.status(500).json({ message: 'Server error fetching project' });
  }
});

// Update Project
app.put('/api/projects/:id', authMiddleware, async (req, res) => {
  try {
    const project = await Project.findOneAndUpdate(
      { _id: req.params.id, userId: req.user._id },
      { $set: req.body },
      { new: true }
    );

    if (!project) {
      return res.status(404).json({ message: 'Project not found' });
    }

    res.json({
      message: 'Project updated successfully',
      project
    });
  } catch (error) {
    console.error('Update project error:', error);
    res.status(500).json({ message: 'Server error updating project' });
  }
});

// Delete Project
app.delete('/api/projects/:id', authMiddleware, async (req, res) => {
  try {
    const project = await Project.findOneAndDelete({
      _id: req.params.id,
      userId: req.user._id
    });

    if (!project) {
      return res.status(404).json({ message: 'Project not found' });
    }

    res.json({ message: 'Project deleted successfully' });
  } catch (error) {
    console.error('Delete project error:', error);
    res.status(500).json({ message: 'Server error deleting project' });
  }
});

// ==================== PAYMENT ROUTES ====================

// Initialize Payment
app.post('/api/payment/init', authMiddleware, async (req, res) => {
  try {
    const { projectId, amount } = req.body;

    // Generate unique reference
    const reference = `OSI-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    const payment = new Payment({
      userId: req.user._id,
      projectId: projectId || null,
      reference,
      amount: amount || 0,
      status: 'pending'
    });

    await payment.save();

    // If projectId provided, update project with payment reference
    if (projectId) {
      await Project.findByIdAndUpdate(projectId, {
        paymentRef: reference
      });
    }

    res.json({
      message: 'Payment initialized',
      ref: reference,
      amount: amount || 0
    });
  } catch (error) {
    console.error('Payment init error:', error);
    res.status(500).json({ message: 'Server error initializing payment' });
  }
});

// Verify Payment
app.get('/api/payment/verify/:reference', authMiddleware, async (req, res) => {
  try {
    const payment = await Payment.findOne({
      reference: req.params.reference,
      userId: req.user._id
    });

    if (!payment) {
      return res.status(404).json({ message: 'Payment not found' });
    }

    res.json({
      reference: payment.reference,
      status: payment.status,
      amount: payment.amount
    });
  } catch (error) {
    console.error('Verify payment error:', error);
    res.status(500).json({ message: 'Server error verifying payment' });
  }
});

// ==================== DASHBOARD ROUTES ====================

// Get Dashboard Summary
app.get('/api/dashboard/summary', authMiddleware, async (req, res) => {
  try {
    const projects = await Project.find({ userId: req.user._id });

    const total = projects.length;
    const pending = projects.filter(p => p.status === 'pending').length;
    const active = projects.filter(p => p.status === 'active').length;
    const completed = projects.filter(p => p.status === 'completed').length;

    res.json({
      total,
      pending,
      active,
      completed,
      recentProjects: projects.slice(-5).reverse()
    });
  } catch (error) {
    console.error('Dashboard summary error:', error);
    res.status(500).json({ message: 'Server error fetching dashboard data' });
  }
});

// ==================== ERROR HANDLING ====================

// 404 Handler
app.use((req, res) => {
  res.status(404).json({ message: 'Route not found' });
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error('Global error:', err);
  res.status(500).json({ message: 'Internal server error' });
});

// ==================== SERVER START ====================

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 OSI Enterprises Backend running on port ${PORT}`);
  console.log(`📡 API available at: http://localhost:${PORT}`);
});