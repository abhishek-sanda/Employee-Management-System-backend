// Express app, middleware, routes, error handler
require('dotenv').config();
// require('express-async-errors'); // handle async errors without try/catch
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');

const authRoutes = require('./routes/auth.routes');
const employeeRoutes = require('./routes/employee.routes');
const { errorHandler } = require('./middlewares/error.middleware');

const app = express();


// allowlist for frontend origins
const FRONTEND_ORIGINS = (process.env.CORS_ORIGINS || 'http://localhost:3000').split(',');

// CORS config: must be applied before routes and before rate limiter
const corsOptions = {
  origin: function (origin, callback) {
    // allow requests with no origin like mobile apps or curl
    if (!origin) return callback(null, true);
    if (FRONTEND_ORIGINS.indexOf(origin) !== -1) {
      return callback(null, true);
    }
    return callback(new Error('CORS not allowed from this origin'), false);
  },
  credentials: true, // allow cookies to be sent
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept']
};

app.use(cors(corsOptions));

// Explicitly respond to preflight for all routes (optional but useful)
app.options(/.*/, cors(corsOptions));

// Basic security middlewares
app.use(helmet());
// Body parsing, cookie parser, etc.
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Logging
if (process.env.NODE_ENV !== 'production') {
  app.use(morgan('dev'));
}

// Rate limiter (adjust per-route for auth endpoints if needed)
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 200
});
app.use(limiter);

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/employees', employeeRoutes);

// Health
app.get('/health', (_req, res) => res.json({ ok: true }));

// Error handler
app.use(errorHandler);

module.exports = app;