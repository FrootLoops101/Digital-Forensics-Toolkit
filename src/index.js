#!/usr/bin/env node

/**
 * Digital Forensics Toolkit - Main Entry Point
 * 
 * This application provides comprehensive digital forensics capabilities including:
 * - Evidence acquisition and management
 * - Chain of custody tracking
 * - Digital analysis and investigation
 * - Automated reporting and documentation
 * - Forensic integrity verification
 */

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const path = require('path');

// Core modules
const EvidenceManager = require('./core/evidence-manager');
const CaseManager = require('./core/case-manager');
const HashCalculator = require('./core/hash-calculator');
const Logger = require('./core/logger');

// Database initialization
const DatabaseConnector = require('../lib/database-connector');

// Configuration
const config = require('../config/tool-configuration.json');

class DigitalForensicsToolkit {
  constructor() {
    this.app = express();
    this.port = process.env.PORT || config.server.port || 3000;
    this.logger = new Logger();
    this.evidenceManager = null;
    this.caseManager = null;
    this.hashCalculator = null;
    this.dbConnector = null;
    
    this.initializeMiddleware();
    this.initializeSecurity();
    this.initializeRoutes();
  }

  async initialize() {
    try {
      this.logger.info('Initializing Digital Forensics Toolkit...');
      
      // Initialize database connection
      this.dbConnector = new DatabaseConnector();
      await this.dbConnector.connect();
      this.logger.info('Database connection established');
      
      // Initialize core modules
      this.evidenceManager = new EvidenceManager(this.dbConnector, this.logger);
      this.caseManager = new CaseManager(this.dbConnector, this.logger);
      this.hashCalculator = new HashCalculator(this.logger);
      
      // Make database connector available to routes
      this.app.locals.dbConnector = this.dbConnector;
      
      this.logger.info('Core modules initialized successfully');
      
      // Start the server
      this.startServer();
      
    } catch (error) {
      this.logger.error('Failed to initialize toolkit:', error);
      process.exit(1);
    }
  }

  initializeMiddleware() {
    // Basic middleware
    this.app.use(express.json({ limit: '50mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '50mb' }));
    this.app.use(compression());
    
    // Serve static files
    this.app.use(express.static(path.join(__dirname, '../public')));
    
    // CORS configuration
    this.app.use(cors({
      origin: config.security.allowedOrigins || ['http://localhost:3000'],
      credentials: true
    }));
  }

  initializeSecurity() {
    // Security headers
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", "data:", "https:"],
        },
      },
    }));

    // Rate limiting
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // limit each IP to 100 requests per windowMs
      message: 'Too many requests from this IP, please try again later.'
    });
    this.app.use('/api/', limiter);
  }

  initializeRoutes() {
    // Health check endpoint
    this.app.get('/health', (req, res) => {
      res.status(200).json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: require('../package.json').version
      });
    });

    // Serve main HTML page
    this.app.get('/', (req, res) => {
      res.sendFile(path.join(__dirname, '../public/index.html'));
    });

    // API routes
    this.app.use('/api/evidence', require('./core/evidence-routes'));
    this.app.use('/api/cases', require('./core/case-routes'));
    this.app.use('/api/acquisition', require('./acquisition/acquisition-routes'));
    this.app.use('/api/analysis', require('./analysis/analysis-routes'));
    this.app.use('/api/reports', require('./reporting/report-routes'));

    // Error handling middleware
    this.app.use((err, req, res, next) => {
      this.logger.error('Unhandled error:', err);
      res.status(500).json({
        error: 'Internal server error',
        message: config.server.showErrors ? err.message : 'An unexpected error occurred'
      });
    });

    // 404 handler
    this.app.use('*', (req, res) => {
      res.status(404).json({
        error: 'Not found',
        message: 'The requested resource was not found'
      });
    });
  }

  startServer() {
    this.app.listen(this.port, () => {
      this.logger.info(`Digital Forensics Toolkit running on port ${this.port}`);
      this.logger.info(`Health check available at http://localhost:${this.port}/health`);
      this.logger.info('Toolkit initialization complete');
    });
  }

  async shutdown() {
    this.logger.info('Shutting down Digital Forensics Toolkit...');
    
    if (this.dbConnector) {
      await this.dbConnector.disconnect();
    }
    
    process.exit(0);
  }
}

// Handle graceful shutdown
process.on('SIGTERM', () => {
  if (global.toolkit) {
    global.toolkit.shutdown();
  }
});

process.on('SIGINT', () => {
  if (global.toolkit) {
    global.toolkit.shutdown();
  }
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  if (global.toolkit) {
    global.toolkit.shutdown();
  }
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  if (global.toolkit) {
    global.toolkit.shutdown();
  }
});

// Start the application
if (require.main === module) {
  global.toolkit = new DigitalForensicsToolkit();
  global.toolkit.initialize().catch((error) => {
    console.error('Failed to initialize Digital Forensics Toolkit:', error);
    process.exit(1);
  });
}

module.exports = DigitalForensicsToolkit;
