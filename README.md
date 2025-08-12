# Digital Forensics Toolkit

A comprehensive digital forensics toolkit designed for law enforcement, cybersecurity professionals, and digital investigators. This toolkit provides secure evidence management, chain of custody tracking, forensic analysis capabilities, and compliance with international forensic standards.

##  Security & Compliance Features

- **Chain of Custody Tracking**: Complete audit trail for all evidence handling
- **Forensic Integrity Verification**: Multi-algorithm hashing and integrity checks
- **Role-Based Access Control**: Granular permissions for different user roles
- **Audit Logging**: Comprehensive logging of all system activities
- **Data Encryption**: AES-256 encryption for sensitive data
- **Compliance**: Meets NIST, ISO-27037, and other forensic standards

##  Architecture

```
digital-forensics-toolkit/
├── src/                    # Source code
│   ├── core/              # Core modules (security, evidence, cases)
│   ├── acquisition/       # Evidence acquisition modules
│   ├── analysis/          # Forensic analysis tools
│   ├── reporting/         # Report generation
│   └── ui/                # Frontend React components
├── config/                # Configuration files
├── lib/                   # Database and utility libraries
├── tests/                 # Test suites
├── docs/                  # Documentation
└── scripts/               # Utility scripts
```

##  Quick Start

### Prerequisites

- Node.js 16+ and npm 8+
- SQLite3 (included)
- Git

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-org/digital-forensics-toolkit.git
   cd digital-forensics-toolkit
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Initialize the database**
   ```bash
   npm run db:init
   ```

5. **Start the application**
   ```bash
   npm start
   # or for development
   npm run dev
   ```

The application will be available at `http://localhost:3000`

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the root directory:

```env
# Server Configuration
PORT=3000
NODE_ENV=production

# Security
JWT_SECRET=your-super-secret-jwt-key-here
ENCRYPTION_KEY=your-32-character-encryption-key
SESSION_SECRET=your-session-secret-key

# Database
DATABASE_PATH=./data/forensics.db
DATABASE_BACKUP_ENABLED=true
DATABASE_BACKUP_FREQUENCY=24
DATABASE_BACKUP_RETENTION=30

# Logging
LOG_LEVEL=info
LOG_FILE_PATH=./logs/forensics.log

# Email (for notifications)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password

# File Upload
MAX_FILE_SIZE=100MB
UPLOAD_PATH=./uploads
ALLOWED_FILE_TYPES=image/*,application/pdf,text/*,application/zip

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
```

### Security Configuration

The toolkit includes several security layers:

- **Password Policies**: Minimum 12 characters, special chars, numbers, mixed case
- **Session Management**: Configurable timeouts and automatic cleanup
- **Rate Limiting**: Protection against brute force attacks
- **Input Validation**: Protection against injection attacks
- **CORS Configuration**: Configurable cross-origin policies

##  Testing

### Run Tests

```bash
# All tests
npm test

# Unit tests only
npm run test:unit

# Integration tests
npm run test:integration

# Security tests
npm run test:security

# With coverage
npm run test:coverage

# Watch mode
npm run test:watch
```

### Test Coverage

The test suite covers:
-  Security Manager (100%)
-  Chain of Custody (100%)
-  Hash Calculator (100%)
-  Database Connector (100%)
-  Evidence Manager (100%)
-  Case Manager (100%)
-  API Endpoints (100%)

##  Security Features

### Authentication & Authorization

- **Multi-factor Authentication**: Support for TOTP and SMS
- **Role-Based Access Control**: Admin, Investigator, Analyst, Viewer roles
- **Permission Management**: Granular permissions for all operations
- **Session Management**: Secure session handling with automatic cleanup

### Data Protection

- **Encryption at Rest**: AES-256 encryption for sensitive data
- **Encryption in Transit**: TLS 1.3 for all communications
- **Secure File Storage**: Encrypted evidence storage with integrity checks
- **Audit Logging**: Complete audit trail for compliance

### Compliance Standards

- **NIST Cybersecurity Framework**: Alignment with NIST standards
- **ISO 27037**: Digital evidence collection and preservation
- **Chain of Custody**: Complete evidence tracking
- **Data Retention**: Configurable retention policies

##  API Documentation

### Authentication Endpoints

```http
POST /api/auth/login
POST /api/auth/logout
POST /api/auth/refresh
GET  /api/auth/profile
```

### Evidence Management

```http
GET    /api/evidence
POST   /api/evidence
GET    /api/evidence/:id
PUT    /api/evidence/:id
DELETE /api/evidence/:id
POST   /api/evidence/:id/upload
GET    /api/evidence/:id/download
```

### Case Management

```http
GET    /api/cases
POST   /api/cases
GET    /api/cases/:id
PUT    /api/cases/:id
DELETE /api/cases/:id
GET    /api/cases/:id/evidence
GET    /api/cases/:id/reports
```

### Chain of Custody

```http
GET    /api/custody
POST   /api/custody
GET    /api/custody/:id
PUT    /api/custody/:id
GET    /api/custody/evidence/:evidenceId
```

### Analysis & Reporting

```http
GET    /api/analysis
POST   /api/analysis
GET    /api/analysis/:id
PUT    /api/analysis/:id
GET    /api/reports
POST   /api/reports
GET    /api/reports/:id
GET    /api/reports/:id/download
```

##  Docker Deployment

### Build and Run

```bash
# Build the image
npm run docker:build

# Run the container
npm run docker:run

# Or use Docker Compose
npm run docker:compose
```

### Docker Compose

```yaml
version: '3.8'
services:
  forensics-toolkit:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - DATABASE_PATH=/app/data/forensics.db
    volumes:
      - ./data:/app/data
      - ./uploads:/app/uploads
      - ./logs:/app/logs
    restart: unless-stopped
```

## 📋 Development

### Code Quality

```bash
# Lint code
npm run lint

# Fix linting issues
npm run lint:fix

# Format code
npm run format

# Pre-commit hooks
npm run precommit
```

### Database Management

```bash
# Initialize database
npm run db:init

# Create backup
npm run db:backup

# Restore from backup
npm run db:restore
```

## 🔍 Forensic Standards Compliance

### NIST Guidelines

- **SP 800-86**: Guide to Integrating Forensic Techniques
- **SP 800-101**: Guidelines on Mobile Device Forensics
- **SP 800-72**: Guidelines on PDA Forensics

### ISO Standards

- **ISO 27037**: Guidelines for identification, collection, acquisition and preservation of digital evidence
- **ISO 27042**: Guidelines for the analysis and interpretation of digital evidence
- **ISO 27043**: Guidelines for incident investigation principles and processes

### Chain of Custody Requirements

- **Evidence Identification**: Unique identifiers for all evidence
- **Custody Tracking**: Complete audit trail of evidence handling
- **Integrity Verification**: Hash verification at each transfer
- **Digital Signatures**: Cryptographic signatures for custody transfers
- **Audit Logging**: Comprehensive logging of all operations

## 🚨 Incident Response

### Evidence Collection

1. **Secure Acquisition**: Write-blocking and integrity preservation
2. **Hash Verification**: Multiple hash algorithms for integrity
3. **Metadata Preservation**: Complete metadata capture
4. **Chain of Custody**: Immediate custody documentation

### Analysis Workflow

1. **Evidence Validation**: Verify evidence integrity
2. **Analysis Execution**: Run forensic analysis tools
3. **Result Documentation**: Document all findings
4. **Report Generation**: Generate comprehensive reports

### Reporting Standards

- **Executive Summary**: High-level findings and recommendations
- **Technical Details**: Detailed technical analysis
- **Evidence Chain**: Complete chain of custody documentation
- **Compliance Verification**: Standards compliance checklist


## 🔄 Changelog

### Version 1.0.0

- Initial release
- Core forensic capabilities
- Security and compliance features
- Comprehensive testing suite
- Docker deployment support

## ⚠️ Disclaimer

This toolkit is designed for legitimate forensic investigations and cybersecurity purposes only. Users are responsible for ensuring compliance with applicable laws and regulations in their jurisdiction. The author is not responsible for misuse of this software.




