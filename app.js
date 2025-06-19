const express = require('express');
const morgan = require('morgan');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');
const mongoose = require('mongoose');
const passport = require('passport');
const session = require('express-session');
const MongoStore = require('connect-mongo');

// Load env vars
require('dotenv').config({ path: './config/config.env' });

// Route files
const auth = require('./routes/authRoutes');
const users = require('./routes/userRoutes');
const kyc = require('./routes/kycRoutes');
const Orders = require('./routes/orderRoutes');


const app = express();

// Body parser
app.use(express.json());

// Dev logging middleware
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// Enable CORS
app.use(cors());
app.use(cors({
  origin: 'https://localhost:5173',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true, // if you want to allow cookies/auth headers
}));


// Set security headers
app.use(helmet());

  // Session configuration with MongoDB storage
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGO_URI,
    collectionName: 'sessions'
  }),
  cookie: {
    maxAge: 1000 * 60 * 60 * 24, // 1 day
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
  }
}));

// Initialize Passport
require('./config/passport');
app.use(passport.initialize());
app.use(passport.session());

// DB Connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error(err));

// Mount routers
app.use('/api/auth', auth);
app.use('/api/users', users);
app.use('/api/kyc', kyc);
app.use('/api/orders', Orders);


// Error handler middleware
const errorHandler = require('./middlewares/error');
app.use(errorHandler);


// Static assets (React build)
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

module.exports = app;