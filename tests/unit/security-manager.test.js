/**
 * Unit Tests for SecurityManager
 * 
 * Tests cover:
 * - Authentication and authorization
 * - Password validation and hashing
 * - JWT token management
 * - Permission checking
 * - Security policies
 * - Audit logging
 */

const SecurityManager = require('../../src/core/security-manager');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Mock dependencies
const mockLogger = {
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn()
};

const mockDbConnector = {
  query: jest.fn(),
  execute: jest.fn()
};

describe('SecurityManager', () => {
  let securityManager;

  beforeEach(() => {
    jest.clearAllMocks();
    securityManager = new SecurityManager(mockLogger, mockDbConnector);
  });

  describe('Constructor', () => {
    test('should initialize with default security policies', () => {
      expect(securityManager.securityPolicies.passwordMinLength).toBe(12);
      expect(securityManager.securityPolicies.requireSpecialChars).toBe(true);
      expect(securityManager.securityPolicies.maxLoginAttempts).toBe(5);
      expect(securityManager.securityPolicies.sessionTimeout).toBe(8 * 60 * 60 * 1000);
    });

    test('should initialize with custom security policies', () => {
      const customPolicies = {
        passwordMinLength: 16,
        maxLoginAttempts: 3
      };
      const customManager = new SecurityManager(mockLogger, mockDbConnector, customPolicies);
      
      expect(customManager.securityPolicies.passwordMinLength).toBe(16);
      expect(customManager.securityPolicies.maxLoginAttempts).toBe(3);
    });
  });

  describe('Password Validation', () => {
    test('should validate strong password', () => {
      const strongPassword = 'StrongPass123!@#';
      expect(() => securityManager.validatePasswordStrength(strongPassword)).not.toThrow();
    });

    test('should reject weak password - too short', () => {
      const weakPassword = 'Weak123!';
      expect(() => securityManager.validatePasswordStrength(weakPassword)).toThrow(/at least 12 characters/);
    });

    test('should reject weak password - no special characters', () => {
      const weakPassword = 'WeakPassword123';
      expect(() => securityManager.validatePasswordStrength(weakPassword)).toThrow(/special character/);
    });

    test('should reject weak password - no numbers', () => {
      const weakPassword = 'WeakPassword!@#';
      expect(() => securityManager.validatePasswordStrength(weakPassword)).toThrow(/number/);
    });

    test('should reject weak password - no uppercase', () => {
      const weakPassword = 'weakpassword123!@#';
      expect(() => securityManager.validatePasswordStrength(weakPassword)).toThrow(/uppercase/);
    });

    test('should reject weak password - no lowercase', () => {
      const weakPassword = 'WEAKPASSWORD123!@#';
      expect(() => securityManager.validatePasswordStrength(weakPassword)).toThrow(/lowercase/);
    });
  });

  describe('Password Hashing', () => {
    test('should hash password with salt', async () => {
      const password = 'TestPassword123!@#';
      const hashedPassword = await securityManager.hashPassword(password);
      
      expect(hashedPassword).not.toBe(password);
      expect(hashedPassword).toMatch(/^\$2[aby]\$\d{1,2}\$[./A-Za-z0-9]{53}$/);
    });

    test('should reject weak password during hashing', async () => {
      const weakPassword = 'weak';
      
      await expect(securityManager.hashPassword(weakPassword)).rejects.toThrow(/Password validation failed/);
    });

    test('should verify correct password', async () => {
      const password = 'TestPassword123!@#';
      const hashedPassword = await securityManager.hashPassword(password);
      
      const isValid = await bcrypt.compare(password, hashedPassword);
      expect(isValid).toBe(true);
    });

    test('should reject incorrect password', async () => {
      const password = 'TestPassword123!@#';
      const hashedPassword = await securityManager.hashPassword(password);
      
      const isValid = await bcrypt.compare('WrongPassword123!@#', hashedPassword);
      expect(isValid).toBe(false);
    });
  });

  describe('User Authentication', () => {
    const mockUser = {
      userId: 'USER-001',
      username: 'testuser',
      passwordHash: '$2a$12$test.hash.here',
      role: 'analyst',
      permissions: ['read:cases', 'read:evidence']
    };

    beforeEach(() => {
      mockDbConnector.query.mockResolvedValue([mockUser]);
    });

    test('should authenticate valid user', async () => {
      // Mock bcrypt.compare to return true
      jest.spyOn(bcrypt, 'compare').mockResolvedValue(true);
      
      const result = await securityManager.authenticateUser('testuser', 'ValidPass123!@#');
      
      expect(result.success).toBe(true);
      expect(result.user.username).toBe('testuser');
      expect(result.user.role).toBe('analyst');
      expect(result.token).toBeDefined();
      expect(result.sessionId).toBeDefined();
    });

    test('should reject invalid credentials', async () => {
      // Mock bcrypt.compare to return false
      jest.spyOn(bcrypt, 'compare').mockResolvedValue(false);
      
      await expect(securityManager.authenticateUser('testuser', 'WrongPass123!@#')).rejects.toThrow('Invalid credentials');
    });

    test('should reject non-existent user', async () => {
      mockDbConnector.query.mockResolvedValue([]);
      
      await expect(securityManager.authenticateUser('nonexistent', 'ValidPass123!@#')).rejects.toThrow('Invalid credentials');
    });

    test('should lock account after multiple failed attempts', async () => {
      // Mock bcrypt.compare to return false
      jest.spyOn(bcrypt, 'compare').mockResolvedValue(false);
      
      // Attempt login multiple times
      for (let i = 0; i < 5; i++) {
        try {
          await securityManager.authenticateUser('testuser', 'WrongPass123!@#');
        } catch (error) {
          // Expected to fail
        }
      }
      
      // Next attempt should be locked
      await expect(securityManager.authenticateUser('testuser', 'ValidPass123!@#')).rejects.toThrow('Account is temporarily locked');
    });

    test('should unlock account after lockout duration', async () => {
      // Mock bcrypt.compare to return false
      jest.spyOn(bcrypt, 'compare').mockResolvedValue(false);
      
      // Attempt login multiple times
      for (let i = 0; i < 5; i++) {
        try {
          await securityManager.authenticateUser('testuser', 'WrongPass123!@#');
        } catch (error) {
          // Expected to fail
        }
      }
      
      // Mock time to pass lockout duration
      const originalDateNow = Date.now;
      Date.now = jest.fn(() => originalDateNow() + 16 * 60 * 1000); // 16 minutes later
      
      // Mock bcrypt.compare to return true
      jest.spyOn(bcrypt, 'compare').mockResolvedValue(true);
      
      // Should work now
      const result = await securityManager.authenticateUser('testuser', 'ValidPass123!@#');
      expect(result.success).toBe(true);
      
      // Restore original Date.now
      Date.now = originalDateNow;
    });
  });

  describe('JWT Token Management', () => {
    const mockUser = {
      userId: 'USER-001',
      username: 'testuser',
      role: 'analyst',
      permissions: ['read:cases']
    };

    test('should generate valid JWT token', () => {
      const token = securityManager.generateJWT(mockUser);
      
      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      
      // Verify token structure
      const parts = token.split('.');
      expect(parts).toHaveLength(3);
    });

    test('should verify valid token', () => {
      const token = securityManager.generateJWT(mockUser);
      const sessionId = 'session-123';
      
      // Mock session to be active
      securityManager.activeSessions.set(sessionId, {
        sessionId,
        userId: mockUser.userId,
        token,
        createdAt: Date.now(),
        lastActivity: Date.now()
      });
      
      const decoded = securityManager.verifyToken(token);
      expect(decoded.userId).toBe(mockUser.userId);
      expect(decoded.username).toBe(mockUser.username);
      expect(decoded.role).toBe(mockUser.role);
    });

    test('should reject expired token', () => {
      // Mock expired token
      const expiredPayload = {
        userId: mockUser.userId,
        username: mockUser.username,
        role: mockUser.role,
        permissions: mockUser.permissions,
        iat: Math.floor(Date.now() / 1000) - 3600, // 1 hour ago
        exp: Math.floor(Date.now() / 1000) - 1800, // 30 minutes ago
        sessionId: 'expired-session'
      };
      
      const expiredToken = jwt.sign(expiredPayload, securityManager.securityPolicies.jwtSecret);
      
      expect(() => securityManager.verifyToken(expiredToken)).toThrow('Invalid or expired token');
    });

    test('should reject invalid token', () => {
      const invalidToken = 'invalid.token.here';
      
      expect(() => securityManager.verifyToken(invalidToken)).toThrow('Invalid or expired token');
    });
  });

  describe('Permission Checking', () => {
    const mockUser = {
      userId: 'USER-001',
      username: 'testuser',
      role: 'analyst',
      permissions: ['read:cases', 'write:analysis']
    };

    beforeEach(() => {
      mockDbConnector.query.mockResolvedValue([mockUser]);
    });

    test('should grant permission for role-based access', async () => {
      const hasPermission = await securityManager.checkPermission('USER-001', 'read', 'cases');
      expect(hasPermission).toBe(true);
    });

    test('should grant permission for user-specific access', async () => {
      const hasPermission = await securityManager.checkPermission('USER-001', 'write', 'analysis');
      expect(hasPermission).toBe(true);
    });

    test('should deny permission for unauthorized action', async () => {
      const hasPermission = await securityManager.checkPermission('USER-001', 'delete', 'cases');
      expect(hasPermission).toBe(false);
    });

    test('should deny permission for non-existent user', async () => {
      mockDbConnector.query.mockResolvedValue([]);
      
      const hasPermission = await securityManager.checkPermission('NONEXISTENT', 'read', 'cases');
      expect(hasPermission).toBe(false);
    });
  });

  describe('Role Permissions', () => {
    test('should return correct permissions for admin role', () => {
      const permissions = securityManager.getRolePermissions('admin');
      
      expect(permissions).toContain('read:all');
      expect(permissions).toContain('write:all');
      expect(permissions).toContain('manage:users');
      expect(permissions).toContain('system:admin');
    });

    test('should return correct permissions for investigator role', () => {
      const permissions = securityManager.getRolePermissions('investigator');
      
      expect(permissions).toContain('read:cases');
      expect(permissions).toContain('write:cases');
      expect(permissions).toContain('read:evidence');
      expect(permissions).toContain('write:evidence');
    });

    test('should return correct permissions for analyst role', () => {
      const permissions = securityManager.getRolePermissions('analyst');
      
      expect(permissions).toContain('read:cases');
      expect(permissions).toContain('read:evidence');
      expect(permissions).toContain('write:analysis');
      expect(permissions).toContain('read:reports');
    });

    test('should return correct permissions for viewer role', () => {
      const permissions = securityManager.getRolePermissions('viewer');
      
      expect(permissions).toContain('read:cases');
      expect(permissions).toContain('read:evidence');
      expect(permissions).toContain('read:reports');
    });

    test('should return empty array for unknown role', () => {
      const permissions = securityManager.getRolePermissions('unknown');
      expect(permissions).toEqual([]);
    });
  });

  describe('Data Encryption', () => {
    test('should encrypt and decrypt data correctly', () => {
      const originalData = 'Sensitive forensic data';
      
      const encrypted = securityManager.encryptData(originalData);
      expect(encrypted.encrypted).toBeDefined();
      expect(encrypted.iv).toBeDefined();
      expect(encrypted.algorithm).toBe('aes-256-cbc');
      
      const decrypted = securityManager.decryptData(encrypted.encrypted, encrypted.iv);
      expect(decrypted).toBe(originalData);
    });

    test('should handle encryption errors gracefully', () => {
      // Mock crypto.createCipher to throw error
      const originalCreateCipher = require('crypto').createCipher;
      require('crypto').createCipher = jest.fn(() => {
        throw new Error('Encryption failed');
      });
      
      expect(() => securityManager.encryptData('test')).toThrow('Encryption failed');
      
      // Restore original function
      require('crypto').createCipher = originalCreateCipher;
    });
  });

  describe('User Management', () => {
    test('should create new user account', async () => {
      const userData = {
        username: 'newuser',
        password: 'NewUserPass123!@#',
        role: 'analyst',
        email: 'newuser@example.com',
        fullName: 'New User'
      };
      
      // Mock password hashing
      jest.spyOn(securityManager, 'hashPassword').mockResolvedValue('hashedPassword123');
      
      // Mock database storage
      mockDbConnector.execute.mockResolvedValue({ lastID: 1 });
      
      const result = await securityManager.createUser(userData);
      
      expect(result.username).toBe('newuser');
      expect(result.role).toBe('analyst');
      expect(result.userId).toMatch(/^USER-\d+-[a-f0-9]+$/);
    });

    test('should update user permissions', async () => {
      const userId = 'USER-001';
      const newPermissions = ['read:all', 'write:cases'];
      
      mockDbConnector.execute.mockResolvedValue({ changes: 1 });
      
      const result = await securityManager.updateUserPermissions(userId, newPermissions);
      expect(result).toBe(true);
      
      expect(mockDbConnector.execute).toHaveBeenCalledWith(
        'UPDATE users SET permissions = ? WHERE user_id = ?',
        [JSON.stringify(newPermissions), userId]
      );
    });
  });

  describe('Session Management', () => {
    test('should create user session', () => {
      const userId = 'USER-001';
      const token = 'jwt.token.here';
      
      const session = securityManager.createSession(userId, token);
      
      expect(session.sessionId).toBeDefined();
      expect(session.userId).toBe(userId);
      expect(session.token).toBe(token);
      expect(session.createdAt).toBeDefined();
      expect(session.lastActivity).toBeDefined();
    });

    test('should check session activity', () => {
      const userId = 'USER-001';
      const token = 'jwt.token.here';
      
      const session = securityManager.createSession(userId, token);
      
      expect(securityManager.isSessionActive(session.sessionId)).toBe(true);
    });

    test('should revoke user session', () => {
      const userId = 'USER-001';
      const token = 'jwt.token.here';
      
      const session = securityManager.createSession(userId, token);
      expect(securityManager.isSessionActive(session.sessionId)).toBe(true);
      
      const result = securityManager.revokeSession(session.sessionId);
      expect(result).toBe(true);
      expect(securityManager.isSessionActive(session.sessionId)).toBe(false);
    });
  });

  describe('Rate Limiting', () => {
    test('should create rate limiter middleware', () => {
      const rateLimiter = securityManager.createRateLimiter({
        windowMs: 15 * 60 * 1000,
        max: 100
      });
      
      expect(typeof rateLimiter).toBe('function');
    });

    test('should create rate limiter with custom options', () => {
      const customOptions = {
        windowMs: 5 * 60 * 1000, // 5 minutes
        max: 50,
        message: 'Custom rate limit message'
      };
      
      const rateLimiter = securityManager.createRateLimiter(customOptions);
      expect(typeof rateLimiter).toBe('function');
    });
  });

  describe('Security Audit Logging', () => {
    test('should log security events', async () => {
      const userId = 'USER-001';
      const action = 'LOGIN_ATTEMPT';
      const details = 'User logged in successfully';
      const ipAddress = '192.168.1.100';
      
      mockDbConnector.execute.mockResolvedValue({ lastID: 1 });
      
      await securityManager.logSecurityEvent(userId, action, details, ipAddress);
      
      expect(mockDbConnector.execute).toHaveBeenCalledWith(
        'INSERT INTO security_audit_log (timestamp, user_id, action, details, ip_address, user_agent, session_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
        expect.arrayContaining([userId, action, details, ipAddress])
      );
    });

    test('should retrieve security audit log', async () => {
      const mockLogEntries = [
        { log_id: 1, action: 'LOGIN_ATTEMPT', user_id: 'USER-001' },
        { log_id: 2, action: 'PERMISSION_DENIED', user_id: 'USER-002' }
      ];
      
      mockDbConnector.query.mockResolvedValue(mockLogEntries);
      
      const filters = { userId: 'USER-001', limit: 10 };
      const results = await securityManager.getSecurityAuditLog(filters);
      
      expect(results).toEqual(mockLogEntries);
      expect(mockDbConnector.query).toHaveBeenCalledWith(
        expect.stringContaining('SELECT * FROM security_audit_log WHERE 1=1'),
        expect.arrayContaining(['USER-001', 10])
      );
    });
  });

  describe('Error Handling', () => {
    test('should handle database connection errors gracefully', async () => {
      mockDbConnector.query.mockRejectedValue(new Error('Database connection failed'));
      
      const hasPermission = await securityManager.checkPermission('USER-001', 'read', 'cases');
      expect(hasPermission).toBe(false);
    });

    test('should handle encryption errors gracefully', () => {
      // Mock crypto to throw error
      const originalCreateCipher = require('crypto').createCipher;
      require('crypto').createCipher = jest.fn(() => {
        throw new Error('Crypto error');
      });
      
      expect(() => securityManager.encryptData('test')).toThrow('Encryption failed');
      
      // Restore original function
      require('crypto').createCipher = originalCreateCipher;
    });
  });
});
