/**
 * Security Manager for Digital Forensics Toolkit
 * 
 * This module provides comprehensive security features including:
 * - Authentication and authorization
 * - Role-based access control
 * - Data encryption and decryption
 * - Security audit logging
 * - Compliance with forensic security standards
 * - Session management
 */

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

class SecurityManager {
  constructor(logger, dbConnector) {
    this.logger = logger;
    this.dbConnector = dbConnector;
    this.activeSessions = new Map();
    this.failedLoginAttempts = new Map();
    this.securityPolicies = {
      passwordMinLength: 12,
      requireSpecialChars: true,
      requireNumbers: true,
      requireUppercase: true,
      requireLowercase: true,
      maxLoginAttempts: 5,
      lockoutDuration: 15 * 60 * 1000, // 15 minutes
      sessionTimeout: 8 * 60 * 60 * 1000, // 8 hours
      jwtSecret: process.env.JWT_SECRET || 'forensic-toolkit-secret-key',
      encryptionKey: process.env.ENCRYPTION_KEY || 'forensic-encryption-key'
    };
  }

  /**
   * Authenticate user with username and password
   * @param {string} username - Username
   * @param {string} password - Password
   * @returns {Object} Authentication result with token
   */
  async authenticateUser(username, password) {
    try {
      // Check for account lockout
      if (this.isAccountLocked(username)) {
        throw new Error('Account is temporarily locked due to multiple failed login attempts');
      }

      // Get user from database
      const user = await this.getUserByUsername(username);
      if (!user) {
        this.recordFailedLogin(username);
        throw new Error('Invalid credentials');
      }

      // Verify password
      const isValidPassword = await bcrypt.compare(password, user.passwordHash);
      if (!isValidPassword) {
        this.recordFailedLogin(username);
        throw new Error('Invalid credentials');
      }

      // Clear failed login attempts
      this.failedLoginAttempts.delete(username);

      // Generate JWT token
      const token = this.generateJWT(user);
      
      // Create session
      const session = this.createSession(user.userId, token);
      
      // Log successful authentication
      this.logger.info(`User authenticated successfully: ${username}`, {
        userId: user.userId,
        role: user.role,
        ipAddress: session.ipAddress
      });

      return {
        success: true,
        token,
        user: {
          userId: user.userId,
          username: user.username,
          role: user.role,
          permissions: user.permissions
        },
        sessionId: session.sessionId
      };

    } catch (error) {
      this.logger.warn(`Authentication failed for user: ${username}`, {
        error: error.message,
        timestamp: new Date().toISOString()
      });
      throw error;
    }
  }

  /**
   * Verify JWT token and return user information
   * @param {string} token - JWT token
   * @returns {Object} Decoded token payload
   */
  verifyToken(token) {
    try {
      const decoded = jwt.verify(token, this.securityPolicies.jwtSecret);
      
      // Check if session is still active
      if (!this.isSessionActive(decoded.sessionId)) {
        throw new Error('Session expired or invalid');
      }

      return decoded;
    } catch (error) {
      this.logger.warn('Token verification failed:', error.message);
      throw new Error('Invalid or expired token');
    }
  }

  /**
   * Check if user has permission for specific action
   * @param {string} userId - User ID
   * @param {string} action - Action to perform
   * @param {string} resource - Resource being accessed
   * @returns {boolean} Permission granted
   */
  async checkPermission(userId, action, resource) {
    try {
      const user = await this.getUserById(userId);
      if (!user) {
        return false;
      }

      // Check role-based permissions
      const rolePermissions = this.getRolePermissions(user.role);
      if (rolePermissions.includes(`${action}:${resource}`)) {
        return true;
      }

      // Check user-specific permissions
      if (user.permissions && user.permissions.includes(`${action}:${resource}`)) {
        return true;
      }

      this.logger.warn(`Permission denied for user ${userId}`, {
        action,
        resource,
        role: user.role
      });

      return false;
    } catch (error) {
      this.logger.error('Error checking permissions:', error);
      return false;
    }
  }

  /**
   * Encrypt sensitive data
   * @param {string} data - Data to encrypt
   * @returns {Object} Encrypted data with IV
   */
  encryptData(data) {
    try {
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipher('aes-256-cbc', this.securityPolicies.encryptionKey);
      
      let encrypted = cipher.update(data, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      return {
        encrypted,
        iv: iv.toString('hex'),
        algorithm: 'aes-256-cbc'
      };
    } catch (error) {
      this.logger.error('Data encryption failed:', error);
      throw new Error('Encryption failed');
    }
  }

  /**
   * Decrypt encrypted data
   * @param {string} encryptedData - Encrypted data
   * @param {string} iv - Initialization vector
   * @returns {string} Decrypted data
   */
  decryptData(encryptedData, iv) {
    try {
      const decipher = crypto.createDecipher('aes-256-cbc', this.securityPolicies.encryptionKey);
      
      let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      this.logger.error('Data decryption failed:', error);
      throw new Error('Decryption failed');
    }
  }

  /**
   * Hash password with salt
   * @param {string} password - Plain text password
   * @returns {string} Hashed password
   */
  async hashPassword(password) {
    try {
      // Validate password strength
      this.validatePasswordStrength(password);
      
      const saltRounds = 12;
      return await bcrypt.hash(password, saltRounds);
    } catch (error) {
      this.logger.error('Password hashing failed:', error);
      throw error;
    }
  }

  /**
   * Validate password strength
   * @param {string} password - Password to validate
   */
  validatePasswordStrength(password) {
    const errors = [];

    if (password.length < this.securityPolicies.passwordMinLength) {
      errors.push(`Password must be at least ${this.securityPolicies.passwordMinLength} characters long`);
    }

    if (this.securityPolicies.requireSpecialChars && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }

    if (this.securityPolicies.requireNumbers && !/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }

    if (this.securityPolicies.requireUppercase && !/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    if (this.securityPolicies.requireLowercase && !/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }

    if (errors.length > 0) {
      throw new Error(`Password validation failed: ${errors.join(', ')}`);
    }
  }

  /**
   * Create new user account
   * @param {Object} userData - User data
   * @returns {Object} Created user
   */
  async createUser(userData) {
    try {
      // Hash password
      const hashedPassword = await this.hashPassword(userData.password);
      
      // Create user object
      const user = {
        userId: this.generateUserId(),
        username: userData.username,
        passwordHash: hashedPassword,
        role: userData.role || 'analyst',
        permissions: userData.permissions || [],
        email: userData.email,
        fullName: userData.fullName,
        createdAt: new Date().toISOString(),
        isActive: true
      };

      // Store in database
      await this.storeUser(user);
      
      this.logger.info(`User account created: ${user.username}`, {
        userId: user.userId,
        role: user.role
      });

      return {
        userId: user.userId,
        username: user.username,
        role: user.role,
        permissions: user.permissions
      };

    } catch (error) {
      this.logger.error('Failed to create user account:', error);
      throw error;
    }
  }

  /**
   * Update user permissions
   * @param {string} userId - User ID
   * @param {Array} permissions - New permissions
   * @returns {boolean} Success status
   */
  async updateUserPermissions(userId, permissions) {
    try {
      await this.dbConnector.execute(
        'UPDATE users SET permissions = ? WHERE user_id = ?',
        [JSON.stringify(permissions), userId]
      );

      this.logger.info(`User permissions updated for user ${userId}`, { permissions });
      return true;
    } catch (error) {
      this.logger.error('Failed to update user permissions:', error);
      return false;
    }
  }

  /**
   * Revoke user session
   * @param {string} sessionId - Session ID to revoke
   * @returns {boolean} Success status
   */
  revokeSession(sessionId) {
    try {
      this.activeSessions.delete(sessionId);
      this.logger.info(`Session revoked: ${sessionId}`);
      return true;
    } catch (error) {
      this.logger.error('Failed to revoke session:', error);
      return false;
    }
  }

  /**
   * Get security audit log
   * @param {Object} filters - Filter criteria
   * @returns {Array} Security audit entries
   */
  async getSecurityAuditLog(filters = {}) {
    try {
      let query = 'SELECT * FROM security_audit_log WHERE 1=1';
      const params = [];

      if (filters.userId) {
        query += ' AND user_id = ?';
        params.push(filters.userId);
      }

      if (filters.action) {
        query += ' AND action = ?';
        params.push(filters.action);
      }

      if (filters.startDate) {
        query += ' AND timestamp >= ?';
        params.push(filters.startDate);
      }

      if (filters.endDate) {
        query += ' AND timestamp <= ?';
        params.push(filters.endDate);
      }

      query += ' ORDER BY timestamp DESC LIMIT ?';
      params.push(filters.limit || 100);

      const results = await this.dbConnector.query(query, params);
      return results;
    } catch (error) {
      this.logger.error('Failed to retrieve security audit log:', error);
      return [];
    }
  }

  /**
   * Log security event
   * @param {string} userId - User ID
   * @param {string} action - Security action
   * @param {string} details - Additional details
   * @param {string} ipAddress - IP address
   */
  async logSecurityEvent(userId, action, details = '', ipAddress = '') {
    try {
      const logEntry = {
        timestamp: new Date().toISOString(),
        userId,
        action,
        details,
        ipAddress,
        userAgent: details.userAgent || '',
        sessionId: details.sessionId || ''
      };

      await this.dbConnector.execute(
        'INSERT INTO security_audit_log (timestamp, user_id, action, details, ip_address, user_agent, session_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [logEntry.timestamp, logEntry.userId, logEntry.action, logEntry.details, logEntry.ipAddress, logEntry.userAgent, logEntry.sessionId]
      );

      this.logger.info(`Security event logged: ${action}`, logEntry);
    } catch (error) {
      this.logger.error('Failed to log security event:', error);
    }
  }

  /**
   * Generate rate limiter middleware
   * @param {Object} options - Rate limiter options
   * @returns {Function} Rate limiter middleware
   */
  createRateLimiter(options = {}) {
    return rateLimit({
      windowMs: options.windowMs || 15 * 60 * 1000, // 15 minutes
      max: options.max || 100, // limit each IP to 100 requests per windowMs
      message: options.message || 'Too many requests from this IP, please try again later.',
      standardHeaders: true,
      legacyHeaders: false,
      handler: (req, res) => {
        this.logger.warn('Rate limit exceeded', {
          ip: req.ip,
          path: req.path,
          timestamp: new Date().toISOString()
        });
        res.status(429).json({
          error: 'Rate limit exceeded',
          message: options.message || 'Too many requests from this IP, please try again later.'
        });
      }
    });
  }

  // Private helper methods

  /**
   * Check if account is locked
   * @param {string} username - Username
   * @returns {boolean} Locked status
   */
  isAccountLocked(username) {
    const attempts = this.failedLoginAttempts.get(username);
    if (!attempts) return false;

    const { count, timestamp } = attempts;
    const now = Date.now();

    if (count >= this.securityPolicies.maxLoginAttempts) {
      if (now - timestamp < this.securityPolicies.lockoutDuration) {
        return true;
      } else {
        // Reset lockout after duration
        this.failedLoginAttempts.delete(username);
        return false;
      }
    }

    return false;
  }

  /**
   * Record failed login attempt
   * @param {string} username - Username
   */
  recordFailedLogin(username) {
    const attempts = this.failedLoginAttempts.get(username) || { count: 0, timestamp: Date.now() };
    attempts.count++;
    attempts.timestamp = Date.now();
    this.failedLoginAttempts.set(username, attempts);
  }

  /**
   * Generate JWT token
   * @param {Object} user - User object
   * @returns {string} JWT token
   */
  generateJWT(user) {
    const payload = {
      userId: user.userId,
      username: user.username,
      role: user.role,
      permissions: user.permissions,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (this.securityPolicies.sessionTimeout / 1000)
    };

    return jwt.sign(payload, this.securityPolicies.jwtSecret);
  }

  /**
   * Create user session
   * @param {string} userId - User ID
   * @param {string} token - JWT token
   * @returns {Object} Session object
   */
  createSession(userId, token) {
    const sessionId = crypto.randomBytes(32).toString('hex');
    const session = {
      sessionId,
      userId,
      token,
      createdAt: Date.now(),
      lastActivity: Date.now(),
      ipAddress: 'unknown', // Would be set from request context
      userAgent: 'unknown'  // Would be set from request context
    };

    this.activeSessions.set(sessionId, session);
    return session;
  }

  /**
   * Check if session is active
   * @param {string} sessionId - Session ID
   * @returns {boolean} Active status
   */
  isSessionActive(sessionId) {
    const session = this.activeSessions.get(sessionId);
    if (!session) return false;

    const now = Date.now();
    if (now - session.lastActivity > this.securityPolicies.sessionTimeout) {
      this.activeSessions.delete(sessionId);
      return false;
    }

    // Update last activity
    session.lastActivity = now;
    return true;
  }

  /**
   * Generate unique user ID
   * @returns {string} Unique user ID
   */
  generateUserId() {
    return `USER-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`;
  }

  /**
   * Get role permissions
   * @param {string} role - User role
   * @returns {Array} Role permissions
   */
  getRolePermissions(role) {
    const rolePermissions = {
      admin: [
        'read:all', 'write:all', 'delete:all', 'manage:users', 'manage:cases',
        'manage:evidence', 'view:audit', 'export:data', 'system:admin'
      ],
      investigator: [
        'read:cases', 'write:cases', 'read:evidence', 'write:evidence',
        'read:reports', 'write:reports', 'export:reports'
      ],
      analyst: [
        'read:cases', 'read:evidence', 'write:analysis', 'read:reports'
      ],
      viewer: [
        'read:cases', 'read:evidence', 'read:reports'
      ]
    };

    return rolePermissions[role] || [];
  }

  /**
   * Get user by username
   * @param {string} username - Username
   * @returns {Object} User object
   */
  async getUserByUsername(username) {
    if (this.dbConnector) {
      const results = await this.dbConnector.query(
        'SELECT * FROM users WHERE username = ? AND is_active = 1',
        [username]
      );
      return results[0];
    }
    return null;
  }

  /**
   * Get user by ID
   * @param {string} userId - User ID
   * @returns {Object} User object
   */
  async getUserById(userId) {
    if (this.dbConnector) {
      const results = await this.dbConnector.query(
        'SELECT * FROM users WHERE user_id = ? AND is_active = 1',
        [userId]
      );
      return results[0];
    }
    return null;
  }

  /**
   * Store user in database
   * @param {Object} user - User object
   */
  async storeUser(user) {
    if (this.dbConnector) {
      await this.dbConnector.execute(
        'INSERT INTO users (user_id, username, password_hash, role, permissions, email, full_name, created_at, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [user.userId, user.username, user.passwordHash, user.role, JSON.stringify(user.permissions), user.email, user.fullName, user.createdAt, user.isActive]
      );
    }
  }
}

module.exports = SecurityManager;
