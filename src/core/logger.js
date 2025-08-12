/**
 * Logger - Core Module
 * 
 * Provides comprehensive logging capabilities for audit trails and system monitoring
 * Implements structured logging with multiple output formats and levels
 */

const winston = require('winston');
const path = require('path');
const fs = require('fs-extra');

class Logger {
  constructor() {
    this.config = require('../../config/tool-configuration.json');
    this.standards = require('../../config/forensic-standards.json');
    this.logger = null;
    this.initializeLogger();
  }

  /**
   * Initialize the Winston logger with custom configuration
   */
  initializeLogger() {
    try {
      // Ensure log directory exists
      const logDir = path.dirname(this.config.logging.file);
      fs.ensureDirSync(logDir);

      // Define custom log format
      const logFormat = winston.format.combine(
        winston.format.timestamp({
          format: 'YYYY-MM-DD HH:mm:ss.SSS'
        }),
        winston.format.errors({ stack: true }),
        winston.format.json()
      );

      // Define console format for development
      const consoleFormat = winston.format.combine(
        winston.format.colorize(),
        winston.format.timestamp({
          format: 'HH:mm:ss'
        }),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
          let metaStr = Object.keys(meta).length ? JSON.stringify(meta, null, 2) : '';
          return `${timestamp} [${level}]: ${message} ${metaStr}`;
        })
      );

      // Create logger instance
      this.logger = winston.createLogger({
        level: this.config.logging.level || 'info',
        format: logFormat,
        defaultMeta: {
          service: 'digital-forensics-toolkit',
          version: require('../../package.json').version
        },
        transports: [
          // File transport for persistent logging
          new winston.transports.File({
            filename: this.config.logging.file,
            maxsize: this.parseSize(this.config.logging.maxSize),
            maxFiles: this.config.logging.maxFiles,
            tailable: true,
            format: logFormat
          }),

          // Error file transport for error-level logs
          new winston.transports.File({
            filename: path.join(logDir, 'errors.log'),
            level: 'error',
            maxsize: this.parseSize(this.config.logging.maxSize),
            maxFiles: this.config.logging.maxFiles,
            tailable: true,
            format: logFormat
          }),

          // Audit log transport for forensic compliance
          new winston.transports.File({
            filename: path.join(logDir, 'audit.log'),
            level: 'info',
            maxsize: this.parseSize(this.config.logging.maxSize),
            maxFiles: this.config.logging.maxFiles,
            tailable: true,
            format: logFormat
          })
        ]
      });

      // Add console transport in development
      if (process.env.NODE_ENV !== 'production') {
        this.logger.add(new winston.transports.Console({
          format: consoleFormat
        }));
      }

      // Handle uncaught exceptions
      this.logger.exceptions.handle(
        new winston.transports.File({
          filename: path.join(logDir, 'exceptions.log'),
          format: logFormat
        })
      );

      // Handle unhandled promise rejections
      this.logger.rejections.handle(
        new winston.transports.File({
          filename: path.join(logDir, 'rejections.log'),
          format: logFormat
        })
      );

      this.logger.info('Logger initialized successfully', {
        logLevel: this.config.logging.level,
        logFile: this.config.logging.file,
        maxSize: this.config.logging.maxSize,
        maxFiles: this.config.logging.maxFiles
      });

    } catch (error) {
      console.error('Failed to initialize logger:', error);
      // Fallback to basic console logging
      this.createFallbackLogger();
    }
  }

  /**
   * Create fallback logger if Winston fails
   */
  createFallbackLogger() {
    this.logger = {
      info: (message, meta) => console.log(`[INFO] ${message}`, meta || ''),
      error: (message, meta) => console.error(`[ERROR] ${message}`, meta || ''),
      warn: (message, meta) => console.warn(`[WARN] ${message}`, meta || ''),
      debug: (message, meta) => console.log(`[DEBUG] ${message}`, meta || ''),
      verbose: (message, meta) => console.log(`[VERBOSE] ${message}`, meta || '')
    };
  }

  /**
   * Log information message
   * @param {string} message - Log message
   * @param {Object} meta - Additional metadata
   */
  info(message, meta = {}) {
    this.logger.info(message, this.enrichMetadata(meta, 'info'));
  }

  /**
   * Log error message
   * @param {string} message - Log message
   * @param {Object} meta - Additional metadata
   */
  error(message, meta = {}) {
    this.logger.error(message, this.enrichMetadata(meta, 'error'));
  }

  /**
   * Log warning message
   * @param {string} message - Log message
   * @param {Object} meta - Additional metadata
   */
  warn(message, meta = {}) {
    this.logger.warn(message, this.enrichMetadata(meta, 'warn'));
  }

  /**
   * Log debug message
   * @param {string} message - Log message
   * @param {Object} meta - Additional metadata
   */
  debug(message, meta = {}) {
    this.logger.debug(message, this.enrichMetadata(meta, 'debug'));
  }

  /**
   * Log verbose message
   * @param {string} message - Log message
   * @param {Object} meta - Additional metadata
   */
  verbose(message, meta = {}) {
    this.logger.verbose(message, this.enrichMetadata(meta, 'verbose'));
  }

  /**
   * Log forensic event for audit trail
   * @param {string} event - Event type
   * @param {string} description - Event description
   * @param {Object} meta - Event metadata
   */
  logForensicEvent(event, description, meta = {}) {
    const forensicMeta = {
      ...meta,
      eventType: 'forensic',
      event: event,
      description: description,
      compliance: {
        nist: this.standards.nist.sp80086.compliance.evidenceCollection.required,
        iso: this.standards.iso['27037'].compliance.identification.required
      }
    };

    this.logger.info(`FORENSIC EVENT: ${event} - ${description}`, forensicMeta);
  }

  /**
   * Log evidence collection event
   * @param {string} evidenceId - Evidence identifier
   * @param {string} action - Collection action
   * @param {Object} meta - Additional metadata
   */
  logEvidenceCollection(evidenceId, action, meta = {}) {
    this.logForensicEvent('evidence_collection', action, {
      evidenceId,
      ...meta
    });
  }

  /**
   * Log custody transfer event
   * @param {string} evidenceId - Evidence identifier
   * @param {string} fromPerson - Previous custodian
   * @param {string} toPerson - New custodian
   * @param {Object} meta - Additional metadata
   */
  logCustodyTransfer(evidenceId, fromPerson, toPerson, meta = {}) {
    this.logForensicEvent('custody_transfer', 'Evidence custody transferred', {
      evidenceId,
      fromPerson,
      toPerson,
      ...meta
    });
  }

  /**
   * Log integrity verification event
   * @param {string} evidenceId - Evidence identifier
   * @param {boolean} verified - Verification result
   * @param {Object} meta - Additional metadata
   */
  logIntegrityVerification(evidenceId, verified, meta = {}) {
    this.logForensicEvent('integrity_verification', 
      verified ? 'Evidence integrity verified' : 'Evidence integrity check failed', {
      evidenceId,
      verified,
      ...meta
    });
  }

  /**
   * Log case management event
   * @param {string} caseId - Case identifier
   * @param {string} action - Case action
   * @param {Object} meta - Additional metadata
   */
  logCaseManagement(caseId, action, meta = {}) {
    this.logForensicEvent('case_management', action, {
      caseId,
      ...meta
    });
  }

  /**
   * Log system security event
   * @param {string} event - Security event type
   * @param {string} description - Event description
   * @param {Object} meta - Additional metadata
   */
  logSecurityEvent(event, description, meta = {}) {
    const securityMeta = {
      ...meta,
      eventType: 'security',
      event: event,
      description: description,
      severity: meta.severity || 'medium'
    };

    this.logger.warn(`SECURITY EVENT: ${event} - ${description}`, securityMeta);
  }

  /**
   * Log user activity for audit trail
   * @param {string} userId - User identifier
   * @param {string} action - User action
   * @param {Object} meta - Additional metadata
   */
  logUserActivity(userId, action, meta = {}) {
    const userMeta = {
      ...meta,
      eventType: 'user_activity',
      userId,
      action,
      timestamp: new Date().toISOString()
    };

    this.logger.info(`USER ACTIVITY: ${userId} - ${action}`, userMeta);
  }

  /**
   * Log performance metrics
   * @param {string} operation - Operation name
   * @param {number} duration - Duration in milliseconds
   * @param {Object} meta - Additional metadata
   */
  logPerformance(operation, duration, meta = {}) {
    const performanceMeta = {
      ...meta,
      eventType: 'performance',
      operation,
      duration,
      timestamp: new Date().toISOString()
    };

    this.logger.debug(`PERFORMANCE: ${operation} - ${duration}ms`, performanceMeta);
  }

  /**
   * Enrich metadata with common forensic information
   * @param {Object} meta - Original metadata
   * @param {string} level - Log level
   * @returns {Object} Enriched metadata
   */
  enrichMetadata(meta, level) {
    return {
      ...meta,
      timestamp: new Date().toISOString(),
      processId: process.pid,
      memoryUsage: process.memoryUsage(),
      uptime: process.uptime(),
      logLevel: level,
      environment: process.env.NODE_ENV || 'development'
    };
  }

  /**
   * Parse size string to bytes
   * @param {string} sizeStr - Size string (e.g., "100MB", "1GB")
   * @returns {number} Size in bytes
   */
  parseSize(sizeStr) {
    if (typeof sizeStr === 'number') return sizeStr;
    
    const units = {
      'B': 1,
      'KB': 1024,
      'MB': 1024 * 1024,
      'GB': 1024 * 1024 * 1024,
      'TB': 1024 * 1024 * 1024 * 1024
    };

    const match = sizeStr.match(/^(\d+(?:\.\d+)?)\s*([KMGT]?B)$/i);
    if (!match) return 100 * 1024 * 1024; // Default to 100MB

    const [, size, unit] = match;
    const unitKey = unit.toUpperCase();
    
    return parseFloat(size) * (units[unitKey] || 1);
  }

  /**
   * Get log statistics
   * @returns {Object} Log statistics
   */
  async getLogStatistics() {
    try {
      const logDir = path.dirname(this.config.logging.file);
      const stats = {
        totalLogs: 0,
        errorLogs: 0,
        warningLogs: 0,
        infoLogs: 0,
        logFiles: [],
        totalSize: 0
      };

      if (await fs.pathExists(logDir)) {
        const files = await fs.readdir(logDir);
        const logFiles = files.filter(file => file.endsWith('.log'));

        for (const file of logFiles) {
          const filePath = path.join(logDir, file);
          const fileStats = await fs.stat(filePath);
          
          stats.logFiles.push({
            name: file,
            size: fileStats.size,
            modified: fileStats.mtime
          });
          
          stats.totalSize += fileStats.size;
        }
      }

      return stats;
    } catch (error) {
      this.error('Failed to get log statistics:', error);
      return { error: error.message };
    }
  }

  /**
   * Rotate log files
   * @returns {boolean} Success status
   */
  async rotateLogs() {
    try {
      const logDir = path.dirname(this.config.logging.file);
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      
      if (await fs.pathExists(logDir)) {
        const files = await fs.readdir(logDir);
        const logFiles = files.filter(file => file.endsWith('.log'));

        for (const file of logFiles) {
          const oldPath = path.join(logDir, file);
          const newPath = path.join(logDir, `${file}.${timestamp}`);
          
          if (await fs.pathExists(oldPath)) {
            await fs.rename(oldPath, newPath);
          }
        }
      }

      this.info('Log rotation completed', { timestamp });
      return true;
    } catch (error) {
      this.error('Failed to rotate logs:', error);
      return false;
    }
  }

  /**
   * Clean old log files
   * @param {number} maxAge - Maximum age in days
   * @returns {boolean} Success status
   */
  async cleanOldLogs(maxAge = 30) {
    try {
      const logDir = path.dirname(this.config.logging.file);
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - maxAge);

      if (await fs.pathExists(logDir)) {
        const files = await fs.readdir(logDir);
        const oldFiles = files.filter(file => {
          if (!file.endsWith('.log')) return false;
          
          const filePath = path.join(logDir, file);
          const stats = fs.statSync(filePath);
          return stats.mtime < cutoffDate;
        });

        for (const file of oldFiles) {
          const filePath = path.join(logDir, file);
          await fs.remove(filePath);
          this.info(`Removed old log file: ${file}`);
        }
      }

      return true;
    } catch (error) {
      this.error('Failed to clean old logs:', error);
      return false;
    }
  }
}

module.exports = Logger;
