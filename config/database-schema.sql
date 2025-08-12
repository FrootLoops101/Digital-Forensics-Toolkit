-- Digital Forensics Toolkit Database Schema
-- This schema supports comprehensive forensic operations including:
-- - User management and authentication
-- - Case management
-- - Evidence tracking and chain of custody
-- - Security audit logging
-- - Analysis results and reporting

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
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    failed_login_attempts INT DEFAULT 0,
    account_locked_until TIMESTAMP NULL
);

-- Cases table for investigation management
CREATE TABLE IF NOT EXISTS cases (
    case_id VARCHAR(50) PRIMARY KEY,
    case_number VARCHAR(100) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    status TEXT CHECK(status IN ('open', 'active', 'closed', 'archived')) DEFAULT 'open',
    priority TEXT CHECK(priority IN ('low', 'medium', 'high', 'critical')) DEFAULT 'medium',
    assigned_investigator VARCHAR(50),
    created_by VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    closed_at TIMESTAMP NULL,
    tags JSON,
    metadata JSON,
    FOREIGN KEY (assigned_investigator) REFERENCES users(user_id),
    FOREIGN KEY (created_by) REFERENCES users(user_id)
);

-- Evidence table for digital evidence management
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id VARCHAR(50) PRIMARY KEY,
    case_id VARCHAR(50) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    type TEXT CHECK(type IN ('file', 'image', 'memory_dump', 'network_capture', 'log_file', 'other')) NOT NULL,
    file_path VARCHAR(500),
    file_size BIGINT,
    file_hash_md5 VARCHAR(32),
    file_hash_sha1 VARCHAR(40),
    file_hash_sha256 VARCHAR(64),
    file_hash_sha512 VARCHAR(128),
    acquisition_method VARCHAR(100),
    acquisition_timestamp TIMESTAMP,
    acquired_by VARCHAR(50) NOT NULL,
    status TEXT CHECK(status IN ('acquired', 'analyzing', 'analyzed', 'archived', 'destroyed')) DEFAULT 'acquired',
    integrity_verified INTEGER DEFAULT 0,
    last_verified TIMESTAMP NULL,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(case_id),
    FOREIGN KEY (acquired_by) REFERENCES users(user_id)
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
    digital_signature VARCHAR(255) NOT NULL,
    integrity_hash VARCHAR(64) NOT NULL,
    previous_custody_id VARCHAR(50) NULL,
    next_custody_id VARCHAR(50) NULL,
    status TEXT CHECK(status IN ('ACTIVE', 'TRANSFERRED', 'CLOSED')) DEFAULT 'ACTIVE',
    closed_timestamp TIMESTAMP NULL,
    FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id),
    FOREIGN KEY (investigator_id) REFERENCES users(user_id),
    FOREIGN KEY (previous_custody_id) REFERENCES chain_of_custody(custody_id),
    FOREIGN KEY (next_custody_id) REFERENCES chain_of_custody(custody_id)
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
    confidence_score DECIMAL(3,2) CHECK (confidence_score >= 0 AND confidence_score <= 1),
    status ENUM('pending', 'in_progress', 'completed', 'failed') DEFAULT 'pending',
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id),
    FOREIGN KEY (analyst_id) REFERENCES users(user_id)
);

-- Reports table
CREATE TABLE IF NOT EXISTS reports (
    report_id VARCHAR(50) PRIMARY KEY,
    case_id VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,
    report_type ENUM('preliminary', 'interim', 'final', 'supplemental') DEFAULT 'final',
    author_id VARCHAR(50) NOT NULL,
    content TEXT,
    summary TEXT,
    conclusions TEXT,
    recommendations TEXT,
    status ENUM('draft', 'review', 'approved', 'published') DEFAULT 'draft',
    version VARCHAR(20) DEFAULT '1.0',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    published_at TIMESTAMP NULL,
    metadata JSON,
    FOREIGN KEY (case_id) REFERENCES cases(case_id),
    FOREIGN KEY (author_id) REFERENCES users(user_id)
);

-- Security audit log table
CREATE TABLE IF NOT EXISTS security_audit_log (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id VARCHAR(50),
    action VARCHAR(100) NOT NULL,
    details TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    session_id VARCHAR(100),
    severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- System configuration table
CREATE TABLE IF NOT EXISTS system_config (
    config_key VARCHAR(100) PRIMARY KEY,
    config_value TEXT,
    config_type ENUM('string', 'number', 'boolean', 'json') DEFAULT 'string',
    description TEXT,
    is_sensitive BOOLEAN DEFAULT FALSE,
    updated_by VARCHAR(50),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (updated_by) REFERENCES users(user_id)
);

-- Evidence tags table for categorization
CREATE TABLE IF NOT EXISTS evidence_tags (
    tag_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id VARCHAR(50) NOT NULL,
    tag_name VARCHAR(100) NOT NULL,
    tag_value TEXT,
    created_by VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id),
    FOREIGN KEY (created_by) REFERENCES users(user_id),
    UNIQUE(evidence_id, tag_name)
);

-- Case notes table
CREATE TABLE IF NOT EXISTS case_notes (
    note_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id VARCHAR(50) NOT NULL,
    author_id VARCHAR(50) NOT NULL,
    note_type ENUM('general', 'investigation', 'analysis', 'finding', 'recommendation') DEFAULT 'general',
    title VARCHAR(255),
    content TEXT NOT NULL,
    is_private BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(case_id),
    FOREIGN KEY (author_id) REFERENCES users(user_id)
);

-- Evidence relationships table
CREATE TABLE IF NOT EXISTS evidence_relationships (
    relationship_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_evidence_id VARCHAR(50) NOT NULL,
    target_evidence_id VARCHAR(50) NOT NULL,
    relationship_type ENUM('derived_from', 'related_to', 'contains', 'part_of', 'similar_to') NOT NULL,
    confidence_score DECIMAL(3,2) CHECK (confidence_score >= 0 AND confidence_score <= 1),
    notes TEXT,
    created_by VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (source_evidence_id) REFERENCES evidence(evidence_id),
    FOREIGN KEY (target_evidence_id) REFERENCES evidence(evidence_id),
    FOREIGN KEY (created_by) REFERENCES users(user_id),
    UNIQUE(source_evidence_id, target_evidence_id, relationship_type)
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_cases_case_number ON cases(case_number);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_assigned_investigator ON cases(assigned_investigator);
CREATE INDEX IF NOT EXISTS idx_evidence_case_id ON evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_evidence_type ON evidence(type);
CREATE INDEX IF NOT EXISTS idx_evidence_status ON evidence(status);
CREATE INDEX IF NOT EXISTS idx_chain_of_custody_evidence_id ON chain_of_custody(evidence_id);
CREATE INDEX IF NOT EXISTS idx_chain_of_custody_investigator_id ON chain_of_custody(investigator_id);
CREATE INDEX IF NOT EXISTS idx_analysis_results_evidence_id ON analysis_results(evidence_id);
CREATE INDEX IF NOT EXISTS idx_analysis_results_analyst_id ON analysis_results(analyst_id);
CREATE INDEX IF NOT EXISTS idx_reports_case_id ON reports(case_id);
CREATE INDEX IF NOT EXISTS idx_reports_author_id ON reports(author_id);
CREATE INDEX IF NOT EXISTS idx_security_audit_log_user_id ON security_audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_security_audit_log_timestamp ON security_audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_security_audit_log_action ON security_audit_log(action);

-- Insert default system configuration
INSERT OR IGNORE INTO system_config (config_key, config_value, config_type, description) VALUES
('system_name', 'Digital Forensics Toolkit', 'string', 'System display name'),
('max_file_size', '1073741824', 'number', 'Maximum file size in bytes (1GB)'),
('allowed_file_types', '["jpg", "png", "gif", "pdf", "doc", "docx", "txt", "log", "pcap", "raw", "dd", "img"]', 'json', 'Allowed file types for evidence'),
('hash_algorithms', '["md5", "sha1", "sha256", "sha512"]', 'json', 'Supported hash algorithms'),
('session_timeout', '28800000', 'number', 'Session timeout in milliseconds (8 hours)'),
('max_login_attempts', '5', 'number', 'Maximum failed login attempts before lockout'),
('lockout_duration', '900000', 'number', 'Account lockout duration in milliseconds (15 minutes)'),
('password_min_length', '12', 'number', 'Minimum password length'),
('require_special_chars', 'true', 'boolean', 'Require special characters in passwords'),
('require_numbers', 'true', 'boolean', 'Require numbers in passwords'),
('require_uppercase', 'true', 'boolean', 'Require uppercase letters in passwords'),
('require_lowercase', 'true', 'boolean', 'Require lowercase letters in passwords'),
('forensic_standards', '["NIST", "ISO_27037", "ACPO"]', 'json', 'Compliant forensic standards'),
('evidence_retention_days', '2555', 'number', 'Evidence retention period in days (7 years)'),
('auto_backup_enabled', 'true', 'boolean', 'Enable automatic database backups'),
('backup_frequency_hours', '24', 'number', 'Database backup frequency in hours'),
('log_retention_days', '365', 'number', 'Log retention period in days'),
('encryption_enabled', 'true', 'boolean', 'Enable data encryption'),
('audit_logging_enabled', 'true', 'boolean', 'Enable security audit logging');

-- Insert default admin user (password: Admin@123456)
INSERT OR IGNORE INTO users (user_id, username, password_hash, full_name, role, email, permissions) VALUES
('ADMIN-001', 'admin', '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/8KqQKqK', 'System Administrator', 'admin', 'admin@forensics.local', '["read:all", "write:all", "delete:all", "manage:users", "manage:cases", "manage:evidence", "view:audit", "export:data", "system:admin"]');

-- Create views for common queries
CREATE VIEW IF NOT EXISTS v_evidence_summary AS
SELECT 
    e.evidence_id,
    e.name,
    e.type,
    e.file_size,
    e.status,
    c.case_number,
    c.title as case_title,
    u.full_name as acquired_by,
    e.created_at,
    e.integrity_verified
FROM evidence e
JOIN cases c ON e.case_id = c.case_id
JOIN users u ON e.acquired_by = u.user_id;

CREATE VIEW IF NOT EXISTS v_case_summary AS
SELECT 
    c.case_id,
    c.case_number,
    c.title,
    c.status,
    c.priority,
    c.created_at,
    u.full_name as assigned_investigator,
    COUNT(e.evidence_id) as evidence_count,
    COUNT(DISTINCT ar.analysis_id) as analysis_count
FROM cases c
LEFT JOIN evidence e ON c.case_id = e.case_id
LEFT JOIN analysis_results ar ON e.evidence_id = ar.evidence_id
LEFT JOIN users u ON c.assigned_investigator = u.user_id
GROUP BY c.case_id;

CREATE VIEW IF NOT EXISTS v_chain_of_custody_summary AS
SELECT 
    coc.custody_id,
    e.name as evidence_name,
    c.case_number,
    u.full_name as investigator,
    coc.location,
    coc.action,
    coc.timestamp,
    coc.status
FROM chain_of_custody coc
JOIN evidence e ON coc.evidence_id = e.evidence_id
JOIN cases c ON e.case_id = c.case_id
JOIN users u ON coc.investigator_id = u.user_id
ORDER BY coc.timestamp DESC;
