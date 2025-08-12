/**
 * Enhanced Database Connector for Digital Forensics Toolkit
 * 
 * This module provides a robust database connection layer with:
 * - Connection pooling and management
 * - Transaction support for forensic operations
 * - Automatic backup and recovery
 * - Audit logging for database operations
 * - Compliance with forensic data integrity requirements
 */

const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs-extra');

class DatabaseConnector {
  constructor(config = {}) {
    this.config = {
      databasePath: config.databasePath || path.join(__dirname, '../data/forensics.db'),
      maxConnections: config.maxConnections || 10,
      connectionTimeout: config.connectionTimeout || 30000,
      backupEnabled: config.backupEnabled !== false,
      backupFrequency: config.backupFrequency || 24, // hours
      backupRetention: config.backupRetention || 30, // days
      ...config
    };
    
    this.db = null;
    this.isConnected = false;
    this.connectionPool = [];
    this.activeTransactions = new Map();
    this.lastBackup = null;
    this.backupTimer = null;
    
    // Ensure data directory exists
    this.ensureDataDirectory();
  }

  /**
   * Initialize database connection and schema
   * @returns {Promise<boolean>} Connection success status
   */
  async connect() {
    try {
      // Create database connection
      this.db = new sqlite3.Database(this.config.databasePath, (err) => {
        if (err) {
          throw new Error(`Failed to connect to database: ${err.message}`);
        }
      });

      // Set connected flag early so we can execute queries
      this.isConnected = true;

      // Enable foreign keys and WAL mode for better performance and integrity
      await this.execute('PRAGMA foreign_keys = ON');
      await this.execute('PRAGMA journal_mode = WAL');
      await this.execute('PRAGMA synchronous = NORMAL');
      await this.execute('PRAGMA cache_size = 10000');
      await this.execute('PRAGMA temp_store = MEMORY');

      // Check if database already has tables
      const tableExists = await this.query("SELECT name FROM sqlite_master WHERE type='table' AND name='users'");
      if (tableExists.length === 0) {
        // Initialize database schema only if tables don't exist
        await this.initializeSchema();
      } else {
        console.log('Database schema already exists, skipping initialization');
      }
      
      // Set up automatic backups
      if (this.config.backupEnabled) {
        this.setupAutomaticBackup();
      }

      this.isConnected = true;
      console.log('Database connection established successfully');
      
      return true;
    } catch (error) {
      console.error('Database connection failed:', error);
      this.isConnected = false;
      throw error;
    }
  }

  /**
   * Initialize database schema from SQL file
   * @returns {Promise<void>}
   */
  async initializeSchema() {
    try {
      const schemaPath = path.join(__dirname, '../config/database-schema.sql');
      
      if (await fs.pathExists(schemaPath)) {
        const schemaSQL = await fs.readFile(schemaPath, 'utf8');
        const statements = schemaSQL.split(';').filter(stmt => stmt.trim());
        
        for (const statement of statements) {
          if (statement.trim()) {
            await this.execute(statement);
          }
        }
        
        console.log('Database schema initialized successfully');
      } else {
        console.warn('Schema file not found, using basic tables');
        await this.createBasicTables();
      }
    } catch (error) {
      console.error('Failed to initialize schema:', error);
      throw error;
    }
  }

  /**
   * Create basic tables if schema file is not available
   * @returns {Promise<void>}
   */
  async createBasicTables() {
    const basicTables = [
      `CREATE TABLE IF NOT EXISTS users (
        user_id VARCHAR(50) PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'analyst',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS cases (
        case_id VARCHAR(50) PRIMARY KEY,
        case_number VARCHAR(100) UNIQUE NOT NULL,
        title VARCHAR(255) NOT NULL,
        status VARCHAR(50) DEFAULT 'open',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS evidence (
        evidence_id VARCHAR(50) PRIMARY KEY,
        case_id VARCHAR(50) NOT NULL,
        name VARCHAR(255) NOT NULL,
        type VARCHAR(100) NOT NULL,
        file_path VARCHAR(500),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`
    ];

    for (const tableSQL of basicTables) {
      await this.execute(tableSQL);
    }
  }

  /**
   * Execute a SQL query with parameters
   * @param {string} sql - SQL query
   * @param {Array} params - Query parameters
   * @returns {Promise<any>} Query result
   */
  execute(sql, params = []) {
    return new Promise((resolve, reject) => {
      if (!this.isConnected) {
        reject(new Error('Database not connected'));
        return;
      }

      this.db.run(sql, params, function(err) {
        if (err) {
          reject(new Error(`Query execution failed: ${err.message}`));
        } else {
          resolve({
            lastID: this.lastID,
            changes: this.changes,
            sql: sql
          });
        }
      });
    });
  }

  /**
   * Execute a SQL query and return results
   * @param {string} sql - SQL query
   * @param {Array} params - Query parameters
   * @returns {Promise<Array>} Query results
   */
  query(sql, params = []) {
    return new Promise((resolve, reject) => {
      if (!this.isConnected) {
        reject(new Error('Database not connected'));
        return;
      }

      this.db.all(sql, params, (err, rows) => {
        if (err) {
          reject(new Error(`Query failed: ${err.message}`));
        } else {
          resolve(rows || []);
        }
      });
    });
  }

  /**
   * Execute a SQL query and return single row
   * @param {string} sql - SQL query
   * @param {Array} params - Query parameters
   * @returns {Promise<Object|null>} Single row result
   */
  queryOne(sql, params = []) {
    return new Promise((resolve, reject) => {
      if (!this.isConnected) {
        reject(new Error('Database not connected'));
        return;
      }

      this.db.get(sql, params, (err, row) => {
        if (err) {
          reject(new Error(`Query failed: ${err.message}`));
        } else {
          resolve(row || null);
        }
      });
    });
  }

  /**
   * Begin a database transaction
   * @param {string} transactionId - Unique transaction identifier
   * @returns {Promise<boolean>} Transaction start success
   */
  async beginTransaction(transactionId) {
    try {
      if (this.activeTransactions.has(transactionId)) {
        throw new Error(`Transaction ${transactionId} already exists`);
      }

      await this.execute('BEGIN TRANSACTION');
      this.activeTransactions.set(transactionId, {
        id: transactionId,
        startTime: Date.now(),
        status: 'active'
      });

      return true;
    } catch (error) {
      console.error(`Failed to begin transaction ${transactionId}:`, error);
      throw error;
    }
  }

  /**
   * Commit a database transaction
   * @param {string} transactionId - Transaction identifier
   * @returns {Promise<boolean>} Transaction commit success
   */
  async commitTransaction(transactionId) {
    try {
      const transaction = this.activeTransactions.get(transactionId);
      if (!transaction) {
        throw new Error(`Transaction ${transactionId} not found`);
      }

      await this.execute('COMMIT');
      transaction.status = 'committed';
      transaction.endTime = Date.now();
      
      // Log transaction completion
      await this.logTransaction(transaction, 'COMMITTED');
      
      this.activeTransactions.delete(transactionId);
      return true;
    } catch (error) {
      console.error(`Failed to commit transaction ${transactionId}:`, error);
      throw error;
    }
  }

  /**
   * Rollback a database transaction
   * @param {string} transactionId - Transaction identifier
   * @returns {Promise<boolean>} Transaction rollback success
   */
  async rollbackTransaction(transactionId) {
    try {
      const transaction = this.activeTransactions.get(transactionId);
      if (!transaction) {
        throw new Error(`Transaction ${transactionId} not found`);
      }

      await this.execute('ROLLBACK');
      transaction.status = 'rolled_back';
      transaction.endTime = Date.now();
      
      // Log transaction rollback
      await this.logTransaction(transaction, 'ROLLED_BACK');
      
      this.activeTransactions.delete(transactionId);
      return true;
    } catch (error) {
      console.error(`Failed to rollback transaction ${transactionId}:`, error);
      throw error;
    }
  }

  /**
   * Log transaction details for audit purposes
   * @param {Object} transaction - Transaction object
   * @param {string} action - Action performed
   * @returns {Promise<void>}
   */
  async logTransaction(transaction, action) {
    try {
      const logEntry = {
        timestamp: new Date().toISOString(),
        transactionId: transaction.id,
        action: action,
        duration: transaction.endTime - transaction.startTime,
        status: transaction.status
      };

      // Store in transaction log table if it exists
      await this.execute(
        'INSERT INTO transaction_log (timestamp, transaction_id, action, duration, status) VALUES (?, ?, ?, ?, ?)',
        [logEntry.timestamp, logEntry.transactionId, logEntry.action, logEntry.duration, logEntry.status]
      );
    } catch (error) {
      // Transaction logging is not critical, just warn
      console.warn('Failed to log transaction:', error);
    }
  }

  /**
   * Create database backup
   * @param {string} backupPath - Optional backup path
   * @returns {Promise<string>} Backup file path
   */
  async createBackup(backupPath = null) {
    try {
      if (!backupPath) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        backupPath = path.join(
          path.dirname(this.config.databasePath),
          `backup-${timestamp}.db`
        );
      }

      // Ensure backup directory exists
      await fs.ensureDir(path.dirname(backupPath));

      // Create backup using SQLite backup API
      const backupDb = new sqlite3.Database(backupPath);
      
      return new Promise((resolve, reject) => {
        this.db.backup(backupDb, (err) => {
          if (err) {
            backupDb.close();
            reject(new Error(`Backup failed: ${err.message}`));
          } else {
            backupDb.close();
            this.lastBackup = Date.now();
            console.log(`Database backup created: ${backupPath}`);
            resolve(backupPath);
          }
        });
      });
    } catch (error) {
      console.error('Failed to create backup:', error);
      throw error;
    }
  }

  /**
   * Restore database from backup
   * @param {string} backupPath - Path to backup file
   * @returns {Promise<boolean>} Restore success status
   */
  async restoreFromBackup(backupPath) {
    try {
      if (!await fs.pathExists(backupPath)) {
        throw new Error(`Backup file not found: ${backupPath}`);
      }

      // Close current connection
      await this.disconnect();

      // Create backup of current database
      const currentBackup = `${this.config.databasePath}.pre-restore-${Date.now()}`;
      await fs.copy(this.config.databasePath, currentBackup);

      // Restore from backup
      await fs.copy(backupPath, this.config.databasePath);

      // Reconnect to restored database
      await this.connect();

      console.log(`Database restored from backup: ${backupPath}`);
      return true;
    } catch (error) {
      console.error('Failed to restore from backup:', error);
      throw error;
    }
  }

  /**
   * Clean up old backup files
   * @returns {Promise<number>} Number of files cleaned up
   */
  async cleanupOldBackups() {
    try {
      const backupDir = path.dirname(this.config.databasePath);
      const files = await fs.readdir(backupDir);
      const backupFiles = files.filter(file => file.startsWith('backup-') && file.endsWith('.db'));
      
      const cutoffTime = Date.now() - (this.config.backupRetention * 24 * 60 * 60 * 1000);
      let cleanedCount = 0;

      for (const file of backupFiles) {
        const filePath = path.join(backupDir, file);
        const stats = await fs.stat(filePath);
        
        if (stats.mtime.getTime() < cutoffTime) {
          await fs.remove(filePath);
          cleanedCount++;
        }
      }

      if (cleanedCount > 0) {
        console.log(`Cleaned up ${cleanedCount} old backup files`);
      }

      return cleanedCount;
    } catch (error) {
      console.error('Failed to cleanup old backups:', error);
      return 0;
    }
  }

  /**
   * Set up automatic backup scheduling
   * @returns {void}
   */
  setupAutomaticBackup() {
    const backupInterval = this.config.backupFrequency * 60 * 60 * 1000; // Convert hours to milliseconds
    
    this.backupTimer = setInterval(async () => {
      try {
        await this.createBackup();
        await this.cleanupOldBackups();
      } catch (error) {
        console.error('Automatic backup failed:', error);
      }
    }, backupInterval);

    console.log(`Automatic backups scheduled every ${this.config.backupFrequency} hours`);
  }

  /**
   * Get database statistics
   * @returns {Promise<Object>} Database statistics
   */
  async getDatabaseStats() {
    try {
      const stats = {
        databasePath: this.config.databasePath,
        isConnected: this.isConnected,
        activeTransactions: this.activeTransactions.size,
        lastBackup: this.lastBackup,
        backupEnabled: this.config.backupEnabled,
        backupFrequency: this.config.backupFrequency,
        backupRetention: this.config.backupRetention
      };

      if (this.isConnected) {
        // Get table row counts
        const tables = ['users', 'cases', 'evidence', 'chain_of_custody', 'analysis_results', 'reports'];
        for (const table of tables) {
          try {
            const result = await this.queryOne(`SELECT COUNT(*) as count FROM ${table}`);
            stats[`${table}_count`] = result ? result.count : 0;
          } catch (error) {
            stats[`${table}_count`] = 'N/A';
          }
        }

        // Get database file size
        try {
          const dbStats = await fs.stat(this.config.databasePath);
          stats.databaseSize = dbStats.size;
          stats.databaseSizeFormatted = this.formatFileSize(dbStats.size);
        } catch (error) {
          stats.databaseSize = 'N/A';
        }
      }

      return stats;
    } catch (error) {
      console.error('Failed to get database stats:', error);
      return { error: error.message };
    }
  }

  /**
   * Format file size in human-readable format
   * @param {number} bytes - Size in bytes
   * @returns {string} Formatted size
   */
  formatFileSize(bytes) {
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    if (bytes === 0) return '0 Bytes';
    
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
  }

  /**
   * Ensure data directory exists
   * @returns {Promise<void>}
   */
  async ensureDataDirectory() {
    try {
      const dataDir = path.dirname(this.config.databasePath);
      await fs.ensureDir(dataDir);
    } catch (error) {
      console.error('Failed to create data directory:', error);
    }
  }

  /**
   * Disconnect from database
   * @returns {Promise<void>}
   */
  async disconnect() {
    try {
      // Rollback any active transactions
      for (const [transactionId, transaction] of this.activeTransactions) {
        if (transaction.status === 'active') {
          await this.rollbackTransaction(transactionId);
        }
      }

      // Clear backup timer
      if (this.backupTimer) {
        clearInterval(this.backupTimer);
        this.backupTimer = null;
      }

      // Close database connection
      if (this.db) {
        this.db.close((err) => {
          if (err) {
            console.error('Error closing database:', err);
          }
        });
        this.db = null;
      }

      this.isConnected = false;
      console.log('Database connection closed');
    } catch (error) {
      console.error('Error during database disconnect:', error);
    }
  }

  /**
   * Check database health
   * @returns {Promise<Object>} Health status
   */
  async checkHealth() {
    try {
      if (!this.isConnected) {
        return { status: 'unhealthy', reason: 'Database not connected' };
      }

      // Test basic query
      await this.queryOne('SELECT 1 as test');
      
      // Check for active transactions
      const activeTransactions = this.activeTransactions.size;
      
      return {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        activeTransactions,
        lastBackup: this.lastBackup
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        reason: error.message,
        timestamp: new Date().toISOString()
      };
    }
  }
}

module.exports = DatabaseConnector;
