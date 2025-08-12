/**
 * Test Setup Configuration
 * 
 * This file configures the testing environment for the digital forensics toolkit.
 * It sets up common test utilities, mocks, and configurations.
 */

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-jwt-secret-key-for-testing-only';
process.env.ENCRYPTION_KEY = 'test-encryption-key-32-chars-long';
process.env.DATABASE_PATH = ':memory:'; // Use in-memory database for tests

// Increase timeout for forensic operations
jest.setTimeout(30000);

// Mock console methods to reduce noise during tests
global.console = {
  ...console,
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};

// Mock file system operations
jest.mock('fs-extra', () => ({
  ...jest.requireActual('fs-extra'),
  ensureDir: jest.fn().mockResolvedValue(undefined),
  pathExists: jest.fn().mockResolvedValue(true),
  readFile: jest.fn().mockResolvedValue('mock file content'),
  writeFile: jest.fn().mockResolvedValue(undefined),
  copy: jest.fn().mockResolvedValue(undefined),
  remove: jest.fn().mockResolvedValue(undefined),
  stat: jest.fn().mockResolvedValue({ size: 1024, mtime: new Date() }),
  readdir: jest.fn().mockResolvedValue(['file1.txt', 'file2.txt']),
  mkdirpSync: jest.fn(),
  existsSync: jest.fn().mockReturnValue(true),
}));

// Mock crypto operations
jest.mock('crypto', () => ({
  ...jest.requireActual('crypto'),
  randomBytes: jest.fn(() => Buffer.from('test-random-bytes')),
  createHash: jest.fn(() => ({
    update: jest.fn().mockReturnThis(),
    digest: jest.fn(() => 'mock-hash-value'),
  })),
  createCipher: jest.fn(() => ({
    update: jest.fn(() => Buffer.from('encrypted')),
    final: jest.fn(() => Buffer.from('final')),
  })),
  createDecipher: jest.fn(() => ({
    update: jest.fn(() => Buffer.from('decrypted')),
    final: jest.fn(() => Buffer.from('final')),
  })),
}));

// Mock bcrypt
jest.mock('bcryptjs', () => ({
  hash: jest.fn().mockResolvedValue('$2a$12$mock.hash.value'),
  compare: jest.fn().mockResolvedValue(true),
  genSalt: jest.fn().mockResolvedValue('$2a$12$mock.salt'),
}));

// Mock JWT
jest.mock('jsonwebtoken', () => ({
  sign: jest.fn((payload, secret, options) => {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64');
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64');
    const signature = 'mock-signature';
    return `${header}.${payloadB64}.${signature}`;
  }),
  verify: jest.fn((token, secret) => {
    if (token === 'invalid.token.here') {
      throw new Error('Invalid token');
    }
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid token format');
    }
    try {
      const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
      return payload;
    } catch (error) {
      throw new Error('Invalid token payload');
    }
  }),
}));

// Mock UUID generation
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'mock-uuid-v4'),
  v5: jest.fn(() => 'mock-uuid-v5'),
}));

// Mock moment.js
jest.mock('moment', () => {
  const moment = jest.requireActual('moment');
  return moment;
});

// Mock winston logger
jest.mock('winston', () => ({
  createLogger: jest.fn(() => ({
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  })),
  format: {
    combine: jest.fn(),
    timestamp: jest.fn(),
    errors: jest.fn(),
    json: jest.fn(),
    simple: jest.fn(),
    colorize: jest.fn(),
  },
  transports: {
    Console: jest.fn(),
    File: jest.fn(),
  },
}));

// Mock express-rate-limit
jest.mock('express-rate-limit', () => {
  return jest.fn().mockImplementation(() => {
    return (req, res, next) => next();
  });
});

// Mock express-slow-down
jest.mock('express-slow-down', () => {
  return jest.fn().mockImplementation(() => {
    return (req, res, next) => next();
  });
});

// Mock multer
jest.mock('multer', () => {
  return jest.fn().mockImplementation(() => {
    return (req, res, next) => next();
  });
});

// Mock sharp for image processing
jest.mock('sharp', () => {
  return jest.fn().mockImplementation(() => ({
    resize: jest.fn().mockReturnThis(),
    jpeg: jest.fn().mockReturnThis(),
    png: jest.fn().mockReturnThis(),
    toBuffer: jest.fn().mockResolvedValue(Buffer.from('mock-image-data')),
    metadata: jest.fn().mockResolvedValue({
      format: 'jpeg',
      width: 1920,
      height: 1080,
      size: 1024,
    }),
  }));
});

// Mock Tesseract.js for OCR
jest.mock('tesseract.js', () => ({
  createWorker: jest.fn().mockResolvedValue({
    loadLanguage: jest.fn().mockResolvedValue(),
    initialize: jest.fn().mockResolvedValue(),
    recognize: jest.fn().mockResolvedValue({
      data: { text: 'Mock OCR text' },
    }),
    terminate: jest.fn().mockResolvedValue(),
  }),
}));

// Mock PDF generation
jest.mock('pdf-lib', () => ({
  PDFDocument: {
    create: jest.fn().mockResolvedValue({
      addPage: jest.fn().mockReturnValue({
        drawText: jest.fn(),
        drawRectangle: jest.fn(),
        drawLine: jest.fn(),
      }),
      save: jest.fn().mockResolvedValue(Buffer.from('mock-pdf-data')),
    }),
    load: jest.fn().mockResolvedValue({
      getPages: jest.fn().mockReturnValue([]),
      save: jest.fn().mockResolvedValue(Buffer.from('mock-pdf-data')),
    }),
  },
  StandardFonts: {
    Helvetica: 'Helvetica',
    TimesRoman: 'TimesRoman',
  },
  rgb: jest.fn(() => ({ r: 0, g: 0, b: 0 })),
}));

// Mock Excel generation
jest.mock('exceljs', () => ({
  Workbook: jest.fn().mockImplementation(() => ({
    addWorksheet: jest.fn().mockReturnValue({
      addRow: jest.fn(),
      addRows: jest.fn(),
      getColumn: jest.fn().mockReturnValue({
        width: 15,
      }),
    }),
    xlsx: {
      writeBuffer: jest.fn().mockResolvedValue(Buffer.from('mock-excel-data')),
    },
  })),
}));

// Global test utilities
global.testUtils = {
  // Generate mock evidence data
  createMockEvidence: (overrides = {}) => ({
    evidenceId: 'EVIDENCE-001',
    caseId: 'CASE-001',
    name: 'Test Evidence File',
    description: 'Test evidence description',
    type: 'file',
    filePath: '/path/to/evidence/file.txt',
    fileSize: 1024,
    fileHashMd5: 'd41d8cd98f00b204e9800998ecf8427e',
    fileHashSha1: 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
    fileHashSha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    acquisitionMethod: 'manual',
    acquiredBy: 'USER-001',
    status: 'acquired',
    integrityVerified: false,
    metadata: {},
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    ...overrides,
  }),

  // Generate mock case data
  createMockCase: (overrides = {}) => ({
    caseId: 'CASE-001',
    caseNumber: 'CASE-2024-001',
    title: 'Test Investigation Case',
    description: 'Test case description',
    status: 'open',
    priority: 'medium',
    assignedInvestigator: 'USER-001',
    createdBy: 'USER-001',
    tags: ['test', 'investigation'],
    metadata: {},
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    ...overrides,
  }),

  // Generate mock user data
  createMockUser: (overrides = {}) => ({
    userId: 'USER-001',
    username: 'testuser',
    passwordHash: '$2a$12$mock.hash.value',
    email: 'testuser@example.com',
    fullName: 'Test User',
    role: 'analyst',
    permissions: ['read:cases', 'read:evidence'],
    isActive: true,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    ...overrides,
  }),

  // Generate mock chain of custody data
  createMockChainOfCustody: (overrides = {}) => ({
    custodyId: 'CUSTODY-001',
    evidenceId: 'EVIDENCE-001',
    investigatorId: 'USER-001',
    location: 'Evidence Room A',
    timestamp: new Date().toISOString(),
    action: 'ACQUISITION',
    notes: 'Evidence acquired from crime scene',
    digitalSignature: 'mock-digital-signature',
    integrityHash: 'mock-integrity-hash',
    status: 'ACTIVE',
    ...overrides,
  }),

  // Generate mock analysis result data
  createMockAnalysisResult: (overrides = {}) => ({
    analysisId: 'ANALYSIS-001',
    evidenceId: 'EVIDENCE-001',
    analystId: 'USER-001',
    analysisType: 'file_analysis',
    analysisTool: 'test-tool',
    analysisParameters: { param1: 'value1' },
    results: { result1: 'finding1' },
    findings: 'Test analysis findings',
    confidenceScore: 0.85,
    status: 'completed',
    startedAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    ...overrides,
  }),

  // Generate mock report data
  createMockReport: (overrides = {}) => ({
    reportId: 'REPORT-001',
    caseId: 'CASE-001',
    title: 'Test Analysis Report',
    reportType: 'final',
    authorId: 'USER-001',
    content: 'Test report content',
    summary: 'Test report summary',
    conclusions: 'Test conclusions',
    recommendations: 'Test recommendations',
    status: 'draft',
    version: '1.0',
    metadata: {},
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    ...overrides,
  }),

  // Wait for async operations
  wait: (ms) => new Promise(resolve => setTimeout(resolve, ms)),

  // Mock file upload
  createMockFileUpload: (filename, mimetype, size) => ({
    fieldname: 'evidence',
    originalname: filename,
    encoding: '7bit',
    mimetype,
    size,
    destination: '/tmp/',
    filename: `mock-${filename}`,
    path: `/tmp/mock-${filename}`,
    buffer: Buffer.from('mock file content'),
  }),

  // Mock request object
  createMockRequest: (overrides = {}) => ({
    body: {},
    params: {},
    query: {},
    headers: {},
    files: [],
    user: null,
    ip: '127.0.0.1',
    method: 'GET',
    url: '/test',
    ...overrides,
  }),

  // Mock response object
  createMockResponse: () => {
    const res = {};
    res.status = jest.fn().mockReturnValue(res);
    res.json = jest.fn().mockReturnValue(res);
    res.send = jest.fn().mockReturnValue(res);
    res.end = jest.fn().mockReturnValue(res);
    res.setHeader = jest.fn().mockReturnValue(res);
    res.getHeader = jest.fn().mockReturnValue(null);
    return res;
  },

  // Mock next function
  createMockNext: () => jest.fn(),

  // Clean up test data
  cleanupTestData: async () => {
    // This would be implemented based on your test database setup
    console.log('Test data cleanup completed');
  },

  // Validate forensic compliance
  validateForensicCompliance: (data) => {
    const complianceChecks = {
      hasTimestamp: !!data.createdAt || !!data.timestamp,
      hasUserId: !!data.userId || !!data.createdBy || !!data.acquiredBy,
      hasIntegrityHash: !!data.integrityHash || !!data.fileHashSha256,
      hasAuditTrail: !!data.auditTrail || !!data.metadata,
    };

    const passedChecks = Object.values(complianceChecks).filter(Boolean).length;
    const totalChecks = Object.keys(complianceChecks).length;

    return {
      compliant: passedChecks === totalChecks,
      score: (passedChecks / totalChecks) * 100,
      details: complianceChecks,
    };
  },
};

// Before each test
beforeEach(() => {
  jest.clearAllMocks();
  jest.clearAllTimers();
});

// After each test
afterEach(() => {
  // Clean up any test data
  if (global.testUtils.cleanupTestData) {
    global.testUtils.cleanupTestData();
  }
});

// After all tests
afterAll(() => {
  // Global cleanup
  jest.restoreAllMocks();
});

// Export test utilities for use in test files
module.exports = global.testUtils;
