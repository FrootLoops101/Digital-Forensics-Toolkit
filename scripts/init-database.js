#!/usr/bin/env node

/**
 * Database Initialization Script
 * 
 * This script initializes the digital forensics toolkit database with:
 * - Complete schema creation
 * - Initial user accounts
 * - Default configurations
 * - Sample data for testing
 * 
 * Usage: node scripts/init-database.js [--reset] [--sample-data]
 */

const fs = require('fs-extra');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

// Configuration
const config = {
  databasePath: process.env.DATABASE_PATH || './data/forensics.db',
  resetDatabase: process.argv.includes('--reset'),
  includeSampleData: process.argv.includes('--sample-data'),
  verbose: process.argv.includes('--verbose') || process.argv.includes('-v'),
  adminPassword: process.env.ADMIN_PASSWORD || 'Admin@123456789',
  adminEmail: process.env.ADMIN_EMAIL || 'admin@forensics-toolkit.com'
};

// Colors for console output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m'
};

function log(message, color = 'reset') {
  const timestamp = new Date().toISOString();
  console.log(`${colors[color]}[${timestamp}] ${message}${colors.reset}`);
}

function logError(message) {
  log(`ERROR: ${message}`, 'red');
}

function logSuccess(message) {
  log(`SUCCESS: ${message}`, 'green');
}

function logInfo(message) {
  log(`INFO: ${message}`, 'blue');
}

function logWarning(message) {
  log(`WARNING: ${message}`, 'yellow');
}

// Database schema
const schema = `
-- Users table for authentication and authorization
CREATE TABLE IF NOT EXISTS users (
    user_id VARCHAR(50) PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE,
    full_name VARCHAR(255) NOT NULL,
    role TEXT CHECK(role IN ('admin', 'investigator', 'analyst', 'viewer')) DEFAULT 'analyst',
    permissions JSON,
    is_active INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP NULL,
    mfa_enabled INTEGER DEFAULT 0,
    mfa_secret VARCHAR(255) NULL,
    mfa_backup_codes JSON NULL
);

-- Cases table for investigation management
CREATE TABLE IF NOT EXISTS cases (
    case_id VARCHAR(50) PRIMARY KEY,
    case_number VARCHAR(100) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    status TEXT CHECK(status IN ('open', 'in_progress', 'closed', 'archived')) DEFAULT 'open',
    priority TEXT CHECK(priority IN ('low', 'medium', 'high', 'critical')) DEFAULT 'medium',
    assigned_investigator VARCHAR(50),
    created_by VARCHAR(50) NOT NULL,
    tags JSON,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP NULL,
    FOREIGN KEY (assigned_investigator) REFERENCES users(user_id),
    FOREIGN KEY (created_by) REFERENCES users(user_id)
);

-- Evidence table for evidence management
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id VARCHAR(50) PRIMARY KEY,
    case_id VARCHAR(50) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    type TEXT CHECK(type IN ('file', 'image', 'document', 'memory_dump', 'network_capture', 'other')) DEFAULT 'file',
    file_path VARCHAR(500),
    file_size BIGINT,
    file_hash_md5 VARCHAR(32),
    file_hash_sha1 VARCHAR(40),
    file_hash_sha256 VARCHAR(64),
    file_hash_sha512 VARCHAR(128),
    acquisition_method TEXT CHECK(acquisition_method IN ('manual', 'automated', 'imaging', 'network', 'memory')) DEFAULT 'manual',
    acquired_by VARCHAR(50) NOT NULL,
    acquired_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT CHECK(status IN ('acquired', 'processing', 'analyzed', 'archived', 'destroyed')) DEFAULT 'acquired',
    integrity_verified INTEGER DEFAULT 0,
    verified_at TIMESTAMP NULL,
    verified_by VARCHAR(50) NULL,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(case_id),
    FOREIGN KEY (acquired_by) REFERENCES users(user_id),
    FOREIGN KEY (verified_by) REFERENCES users(user_id)
);

-- Chain of custody table for evidence tracking
CREATE TABLE IF NOT EXISTS chain_of_custody (
    custody_id VARCHAR(50) PRIMARY KEY,
    evidence_id VARCHAR(50) NOT NULL,
    investigator_id VARCHAR(50) NOT NULL,
    location VARCHAR(255) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    action TEXT CHECK(action IN ('ACQUISITION', 'TRANSFER', 'ANALYSIS', 'STORAGE', 'DESTRUCTION')) NOT NULL,
    notes TEXT,
    digital_signature VARCHAR(500),
    integrity_hash VARCHAR(64),
    previous_custody_id VARCHAR(50) NULL,
    status TEXT CHECK(status IN ('ACTIVE', 'COMPLETED', 'CANCELLED')) DEFAULT 'ACTIVE',
    metadata JSON,
    FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id),
    FOREIGN KEY (investigator_id) REFERENCES users(user_id),
    FOREIGN KEY (previous_custody_id) REFERENCES chain_of_custody(custody_id)
);

-- Analysis results table
CREATE TABLE IF NOT EXISTS analysis_results (
    analysis_id VARCHAR(50) PRIMARY KEY,
    evidence_id VARCHAR(50) NOT NULL,
    analyst_id VARCHAR(50) NOT NULL,
    analysis_type VARCHAR(100) NOT NULL,
    analysis_tool VARCHAR(100),
    analysis_parameters JSON,
    results JSON,
    findings TEXT,
    confidence_score DECIMAL(3,2),
    status TEXT CHECK(status IN ('pending', 'in_progress', 'completed', 'failed')) DEFAULT 'pending',
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    error_message TEXT NULL,
    metadata JSON,
    FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id),
    FOREIGN KEY (analyst_id) REFERENCES users(user_id)
);

-- Reports table
CREATE TABLE IF NOT EXISTS reports (
    report_id VARCHAR(50) PRIMARY KEY,
    case_id VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,
    report_type TEXT CHECK(report_type IN ('preliminary', 'interim', 'final', 'supplemental')) DEFAULT 'final',
    author_id VARCHAR(50) NOT NULL,
    content TEXT,
    summary TEXT,
    conclusions TEXT,
    recommendations TEXT,
    status TEXT CHECK(status IN ('draft', 'review', 'approved', 'published')) DEFAULT 'draft',
    version VARCHAR(20) DEFAULT '1.0',
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    published_at TIMESTAMP NULL,
    FOREIGN KEY (case_id) REFERENCES cases(case_id),
    FOREIGN KEY (author_id) REFERENCES users(user_id)
);

-- Audit log table
CREATE TABLE IF NOT EXISTS audit_log (
    log_id VARCHAR(50) PRIMARY KEY,
    user_id VARCHAR(50) NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(50),
    details JSON,
    ip_address VARCHAR(45),
    user_agent TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    severity TEXT CHECK(severity IN ('info', 'warning', 'error', 'critical')) DEFAULT 'info',
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Security events table
CREATE TABLE IF NOT EXISTS security_events (
    event_id VARCHAR(50) PRIMARY KEY,
    event_type VARCHAR(100) NOT NULL,
    user_id VARCHAR(50) NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    details JSON,
    severity TEXT CHECK(severity IN ('low', 'medium', 'high', 'critical')) DEFAULT 'medium',
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved INTEGER DEFAULT 0,
    resolved_at TIMESTAMP NULL,
    resolved_by VARCHAR(50) NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (resolved_by) REFERENCES users(user_id)
);

-- System configuration table
CREATE TABLE IF NOT EXISTS system_config (
    config_key VARCHAR(100) PRIMARY KEY,
    config_value TEXT,
    config_type TEXT CHECK(config_type IN ('string', 'number', 'boolean', 'json')) DEFAULT 'string',
    description TEXT,
    is_sensitive INTEGER DEFAULT 0,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_by VARCHAR(50) NULL,
    FOREIGN KEY (updated_by) REFERENCES users(user_id)
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_evidence_case_id ON evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_evidence_acquired_by ON evidence(acquired_by);
CREATE INDEX IF NOT EXISTS idx_evidence_status ON evidence(status);
CREATE INDEX IF NOT EXISTS idx_custody_evidence_id ON chain_of_custody(evidence_id);
CREATE INDEX IF NOT EXISTS idx_custody_investigator_id ON chain_of_custody(investigator_id);
CREATE INDEX IF NOT EXISTS idx_analysis_evidence_id ON analysis_results(evidence_id);
CREATE INDEX IF NOT EXISTS idx_analysis_analyst_id ON analysis_results(analyst_id);
CREATE INDEX IF NOT EXISTS idx_reports_case_id ON reports(case_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_security_events_user_id ON security_events(user_id);
CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp);
`;

// Sample data
const sampleData = {
  users: [
    {
      user_id: 'USER-001',
      username: 'admin',
      password_hash: '', // Will be set below
      email: 'admin@forensics-toolkit.com',
      full_name: 'System Administrator',
      role: 'admin',
      permissions: JSON.stringify(['*']),
      is_active: true
    },
    {
      user_id: 'USER-002',
      username: 'investigator1',
      password_hash: '', // Will be set below
      email: 'investigator1@forensics-toolkit.com',
      full_name: 'John Investigator',
      role: 'investigator',
      permissions: JSON.stringify(['read:cases', 'write:cases', 'read:evidence', 'write:evidence', 'read:reports', 'write:reports']),
      is_active: true
    },
    {
      user_id: 'USER-003',
      username: 'analyst1',
      password_hash: '', // Will be set below
      email: 'analyst1@forensics-toolkit.com',
      full_name: 'Jane Analyst',
      role: 'analyst',
      permissions: JSON.stringify(['read:cases', 'read:evidence', 'write:analysis', 'read:reports']),
      is_active: true
    }
  ],
  cases: [
    {
      case_id: 'CASE-001',
      case_number: 'CASE-2024-001',
      title: 'Sample Investigation Case',
      description: 'This is a sample case for demonstration purposes.',
      status: 'open',
      priority: 'medium',
      assigned_investigator: 'USER-002',
      created_by: 'USER-001',
      tags: JSON.stringify(['sample', 'demonstration', 'training'])
    }
  ],
  evidence: [
    {
      evidence_id: 'EVIDENCE-001',
      case_id: 'CASE-001',
      name: 'Sample Evidence File',
      description: 'A sample evidence file for demonstration.',
      type: 'file',
      file_path: '/sample/path/evidence.txt',
      file_size: 1024,
      file_hash_md5: 'd41d8cd98f00b204e9800998ecf8427e',
      file_hash_sha1: 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
      file_hash_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      acquisition_method: 'manual',
      acquired_by: 'USER-002',
      status: 'acquired'
    }
  ],
  systemConfig: [
    {
      config_key: 'system.name',
      config_value: 'Digital Forensics Toolkit',
      config_type: 'string',
      description: 'System name for display purposes'
    },
    {
      config_key: 'system.version',
      config_value: '1.0.0',
      config_type: 'string',
      description: 'Current system version'
    },
    {
      config_key: 'security.password_policy.min_length',
      config_value: '12',
      config_type: 'number',
      description: 'Minimum password length'
    },
    {
      config_key: 'security.password_policy.require_uppercase',
      config_value: 'true',
      config_type: 'boolean',
      description: 'Require uppercase letters in passwords'
    },
    {
      config_key: 'forensics.hash_algorithms',
      config_value: JSON.stringify(['md5', 'sha1', 'sha256', 'sha512']),
      config_type: 'json',
      description: 'Supported hash algorithms'
    }
  ]
};

class DatabaseInitializer {
  constructor() {
    this.db = null;
    this.dbPath = path.resolve(config.databasePath);
  }

  async initialize() {
    try {
      logInfo('Starting database initialization...');
      
      // Ensure data directory exists
      await this.ensureDataDirectory();
      
      // Initialize database connection
      await this.connectDatabase();
      
      // Reset database if requested
      if (config.resetDatabase) {
        await this.resetDatabase();
      }
      
      // Create schema
      await this.createSchema();
      
      // Insert initial data
      await this.insertInitialData();
      
      // Insert sample data if requested
      if (config.includeSampleData) {
        await this.insertSampleData();
      }
      
      // Create views and triggers
      await this.createViewsAndTriggers();
      
      // Verify database integrity
      await this.verifyDatabase();
      
      logSuccess('Database initialization completed successfully!');
      
    } catch (error) {
      logError(`Database initialization failed: ${error.message}`);
      process.exit(1);
    } finally {
      if (this.db) {
        this.db.close();
      }
    }
  }

  async ensureDataDirectory() {
    const dataDir = path.dirname(this.dbPath);
    await fs.ensureDir(dataDir);
    logInfo(`Data directory ensured: ${dataDir}`);
  }

  async connectDatabase() {
    return new Promise((resolve, reject) => {
      this.db = new sqlite3.Database(this.dbPath, (err) => {
        if (err) {
          reject(new Error(`Failed to connect to database: ${err.message}`));
        } else {
          logInfo(`Connected to database: ${this.dbPath}`);
          resolve();
        }
      });
    });
  }

  async resetDatabase() {
    logWarning('Resetting database...');
    
    const tables = [
      'security_events',
      'audit_log',
      'analysis_results',
      'chain_of_custody',
      'evidence',
      'reports',
      'cases',
      'users',
      'system_config'
    ];

    for (const table of tables) {
      await this.executeQuery(`DROP TABLE IF EXISTS ${table}`);
    }
    
    logInfo('Database reset completed');
  }

  async createSchema() {
    logInfo('Creating database schema...');
    
    const statements = schema.split(';').filter(stmt => stmt.trim());
    
    for (const statement of statements) {
      if (statement.trim()) {
        await this.executeQuery(statement);
      }
    }
    
    logSuccess('Database schema created successfully');
  }

  async insertInitialData() {
    logInfo('Inserting initial data...');
    
    // Hash passwords
    const saltRounds = 12;
    for (const user of sampleData.users) {
      user.password_hash = await bcrypt.hash(user.username === 'admin' ? config.adminPassword : 'Password@123', saltRounds);
    }
    
    // Insert users
    for (const user of sampleData.users) {
      await this.executeQuery(`
        INSERT OR REPLACE INTO users (user_id, username, password_hash, email, full_name, role, permissions, is_active)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `, [user.user_id, user.username, user.password_hash, user.email, user.full_name, user.role, user.permissions, user.is_active]);
    }
    
    // Insert system configuration
    for (const configItem of sampleData.systemConfig) {
      await this.executeQuery(`
        INSERT OR REPLACE INTO system_config (config_key, config_value, config_type, description)
        VALUES (?, ?, ?, ?)
      `, [configItem.config_key, configItem.config_value, configItem.config_type, configItem.description]);
    }
    
    logSuccess('Initial data inserted successfully');
  }

  async insertSampleData() {
    logInfo('Inserting sample data...');
    
    // Insert sample case
    for (const caseItem of sampleData.cases) {
      await this.executeQuery(`
        INSERT OR REPLACE INTO cases (case_id, case_number, title, description, status, priority, assigned_investigator, created_by, tags)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [caseItem.case_id, caseItem.case_number, caseItem.title, caseItem.description, caseItem.status, caseItem.priority, caseItem.assigned_investigator, caseItem.created_by, caseItem.tags]);
    }
    
    // Insert sample evidence
    for (const evidence of sampleData.evidence) {
      await this.executeQuery(`
        INSERT OR REPLACE INTO evidence (evidence_id, case_id, name, description, type, file_path, file_size, file_hash_md5, file_hash_sha1, file_hash_sha256, acquisition_method, acquired_by, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [evidence.evidence_id, evidence.case_id, evidence.name, evidence.description, evidence.type, evidence.file_path, evidence.file_size, evidence.file_hash_md5, evidence.file_hash_sha1, evidence.file_hash_sha256, evidence.acquisition_method, evidence.acquired_by, evidence.status]);
    }
    
    // Insert sample chain of custody
    await this.executeQuery(`
      INSERT OR REPLACE INTO chain_of_custody (custody_id, evidence_id, investigator_id, location, action, notes, integrity_hash, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `, ['CUSTODY-001', 'EVIDENCE-001', 'USER-002', 'Evidence Room A', 'ACQUISITION', 'Initial evidence acquisition', 'sample-integrity-hash', 'ACTIVE']);
    
    logSuccess('Sample data inserted successfully');
  }

  async createViewsAndTriggers() {
    logInfo('Creating views and triggers...');
    
    // Create evidence summary view
    await this.executeQuery(`
      CREATE VIEW IF NOT EXISTS evidence_summary AS
      SELECT 
        e.evidence_id,
        e.name,
        e.type,
        e.status,
        e.file_size,
        e.file_hash_sha256,
        c.case_number,
        c.title as case_title,
        u.full_name as acquired_by,
        e.acquired_at
      FROM evidence e
      JOIN cases c ON e.case_id = c.case_id
      JOIN users u ON e.acquired_by = u.user_id
    `);
    
    // Create case summary view
    await this.executeQuery(`
      CREATE VIEW IF NOT EXISTS case_summary AS
      SELECT 
        c.case_id,
        c.case_number,
        c.title,
        c.status,
        c.priority,
        c.created_at,
        COUNT(e.evidence_id) as evidence_count,
        u.full_name as assigned_investigator
      FROM cases c
      LEFT JOIN evidence e ON c.case_id = e.case_id
      LEFT JOIN users u ON c.assigned_investigator = u.user_id
      GROUP BY c.case_id
    `);
    
    // Create audit trigger
    await this.executeQuery(`
      CREATE TRIGGER IF NOT EXISTS audit_evidence_changes
      AFTER UPDATE ON evidence
      BEGIN
        INSERT INTO audit_log (log_id, user_id, action, resource_type, resource_id, details, timestamp)
        VALUES (
          'AUDIT-' || datetime('now', 'unixepoch'),
          NEW.acquired_by,
          'EVIDENCE_UPDATED',
          'evidence',
          NEW.evidence_id,
          json_object(
            'old_status', OLD.status,
            'new_status', NEW.status,
            'old_description', OLD.description,
            'new_description', NEW.description
          ),
          datetime('now')
        );
      END
    `);
    
    logSuccess('Views and triggers created successfully');
  }

  async verifyDatabase() {
    logInfo('Verifying database integrity...');
    
    const tables = await this.query('SELECT name FROM sqlite_master WHERE type="table"');
    logInfo(`Found ${tables.length} tables: ${tables.map(t => t.name).join(', ')}`);
    
    const userCount = await this.query('SELECT COUNT(*) as count FROM users');
    logInfo(`User count: ${userCount[0].count}`);
    
    const caseCount = await this.query('SELECT COUNT(*) as count FROM cases');
    logInfo(`Case count: ${caseCount[0].count}`);
    
    const evidenceCount = await this.query('SELECT COUNT(*) as count FROM evidence');
    logInfo(`Evidence count: ${evidenceCount[0].count}`);
    
    logSuccess('Database verification completed');
  }

  async executeQuery(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.run(sql, params, function(err) {
        if (err) {
          reject(new Error(`Query execution failed: ${err.message}\nSQL: ${sql}`));
        } else {
          if (config.verbose) {
            logInfo(`Executed: ${sql.substring(0, 100)}...`);
          }
          resolve(this);
        }
      });
    });
  }

  async query(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.all(sql, params, (err, rows) => {
        if (err) {
          reject(new Error(`Query failed: ${err.message}\nSQL: ${sql}`));
        } else {
          resolve(rows);
        }
      });
    });
  }
}

// Main execution
async function main() {
  try {
    const initializer = new DatabaseInitializer();
    await initializer.initialize();
    
    logSuccess('Database initialization completed successfully!');
    logInfo(`Database location: ${path.resolve(config.databasePath)}`);
    
    if (config.includeSampleData) {
      logInfo('Sample data has been included for testing purposes');
      logInfo('Default admin credentials: admin / Admin@123456789');
      logInfo('Default user credentials: investigator1 / Password@123');
      logInfo('Default user credentials: analyst1 / Password@123');
    }
    
    logInfo('You can now start the application with: npm start');
    
  } catch (error) {
    logError(`Initialization failed: ${error.message}`);
    process.exit(1);
  }
}

// Run if called directly
if (require.main === module) {
  main();
}

module.exports = DatabaseInitializer;
