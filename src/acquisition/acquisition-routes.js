const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs-extra');
const { v4: uuidv4 } = require('uuid');
const HashCalculator = require('../core/hash-calculator');

// Configure multer for large file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const caseId = req.body.case_id || 'default';
    const uploadPath = path.join(__dirname, '../../data/acquisitions', caseId);
    fs.mkdirpSync(uploadPath);
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const uniqueName = `${timestamp}-${uuidv4()}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 1024 * 1024 * 1024 }, // 1GB limit for acquisitions
  fileFilter: (req, file, cb) => {
    // Allow all file types for acquisitions
    cb(null, true);
  }
});

// Initialize hash calculator
const hashCalculator = new HashCalculator();

// Start new acquisition session
router.post('/session/start', async (req, res) => {
  try {
    const { case_id, acquisition_type, target_description, investigator } = req.body;
    
    if (!case_id || !acquisition_type || !target_description || !investigator) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing required fields: case_id, acquisition_type, target_description, investigator' 
      });
    }
    
    const sessionId = uuidv4();
    const sessionData = {
      id: sessionId,
      case_id,
      acquisition_type,
      target_description,
      investigator,
      start_time: new Date().toISOString(),
      status: 'active',
      evidence_count: 0,
      total_size: 0
    };
    
    // Store session data (in a real implementation, this would go to the database)
    const sessionPath = path.join(__dirname, '../../data/acquisitions', case_id, 'sessions', `${sessionId}.json`);
    await fs.ensureDir(path.dirname(sessionPath));
    await fs.writeJson(sessionPath, sessionData);
    
    res.status(201).json({ 
      success: true, 
      session_id: sessionId,
      session: sessionData,
      message: 'Acquisition session started'
    });
    
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Upload evidence during acquisition
router.post('/evidence/upload', upload.single('evidence_file'), async (req, res) => {
  try {
    const { case_id, session_id, evidence_name, evidence_type, source_location, notes } = req.body;
    const file = req.file;
    
    if (!file) {
      return res.status(400).json({ success: false, error: 'No file uploaded' });
    }
    
    if (!case_id || !session_id || !evidence_name || !evidence_type) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing required fields: case_id, session_id, evidence_name, evidence_type' 
      });
    }
    
    const db = req.app.locals.dbConnector;
    const evidenceId = uuidv4();
    
    // Get file stats
    const stats = await fs.stat(file.path);
    
    // Calculate hashes
    const hashes = await hashCalculator.calculateAllHashes(file.path);
    
    // Store evidence in database
    await db.run(
      `INSERT INTO evidence (
        id, case_id, name, type, source, size_bytes, hash_md5, hash_sha1, hash_sha256, notes, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        evidenceId, case_id, evidence_name, evidence_type, 
        `acquisitions/${case_id}/${path.basename(file.path)}`, 
        stats.size, hashes.md5, hashes.sha1, hashes.sha256, 
        notes, 'acquired'
      ]
    );
    
    // Log acquisition in chain of custody
    await db.run(
      `INSERT INTO evidence_chain (
        id, evidence_id, action, user, details
      ) VALUES (?, ?, ?, ?, ?)`,
      [
        uuidv4(), evidenceId, 'acquired', 
        req.user || 'system', 
        `Evidence acquired during session ${session_id}`
      ]
    );
    
    // Update session file
    const sessionPath = path.join(__dirname, '../../data/acquisitions', case_id, 'sessions', `${session_id}.json`);
    if (await fs.pathExists(sessionPath)) {
      const sessionData = await fs.readJson(sessionPath);
      sessionData.evidence_count += 1;
      sessionData.total_size += stats.size;
      await fs.writeJson(sessionPath, sessionData);
    }
    
    res.json({ 
      success: true, 
      evidence_id: evidenceId,
      file_info: {
        original_name: file.originalname,
        stored_path: file.path,
        size: stats.size,
        hashes
      },
      message: 'Evidence acquired successfully'
    });
    
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// End acquisition session
router.post('/session/:sessionId/end', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const { case_id, final_notes } = req.body;
    
    if (!case_id) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing required field: case_id' 
      });
    }
    
    const sessionPath = path.join(__dirname, '../../data/acquisitions', case_id, 'sessions', `${sessionId}.json`);
    
    if (!(await fs.pathExists(sessionPath))) {
      return res.status(404).json({ success: false, error: 'Session not found' });
    }
    
    const sessionData = await fs.readJson(sessionPath);
    sessionData.status = 'completed';
    sessionData.end_time = new Date().toISOString();
    sessionData.final_notes = final_notes;
    sessionData.duration_minutes = Math.round(
      (new Date(sessionData.end_time) - new Date(sessionData.start_time)) / (1000 * 60)
    );
    
    await fs.writeJson(sessionPath, sessionData);
    
    res.json({ 
      success: true, 
      session: sessionData,
      message: 'Acquisition session completed'
    });
    
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get acquisition session details
router.get('/session/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const { case_id } = req.query;
    
    if (!case_id) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing required query parameter: case_id' 
      });
    }
    
    const sessionPath = path.join(__dirname, '../../data/acquisitions', case_id, 'sessions', `${sessionId}.json`);
    
    if (!(await fs.pathExists(sessionPath))) {
      return res.status(404).json({ success: false, error: 'Session not found' });
    }
    
    const sessionData = await fs.readJson(sessionPath);
    
    // Get evidence acquired during this session
    const db = req.app.locals.dbConnector;
    const evidence = await db.all(
      `SELECT * FROM evidence 
       WHERE case_id = ? AND source LIKE ?`,
      [case_id, `%acquisitions/${case_id}%`]
    );
    
    res.json({ 
      success: true, 
      session: sessionData,
      evidence_acquired: evidence
    });
    
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get all acquisition sessions for a case
router.get('/case/:caseId/sessions', async (req, res) => {
  try {
    const { caseId } = req.params;
    const sessionsPath = path.join(__dirname, '../../data/acquisitions', caseId, 'sessions');
    
    if (!(await fs.pathExists(sessionsPath))) {
      return res.json({ success: true, sessions: [] });
    }
    
    const sessionFiles = await fs.readdir(sessionsPath);
    const sessions = [];
    
    for (const file of sessionFiles) {
      if (file.endsWith('.json')) {
        const sessionData = await fs.readJson(path.join(sessionsPath, file));
        sessions.push(sessionData);
      }
    }
    
    // Sort by start time (newest first)
    sessions.sort((a, b) => new Date(b.start_time) - new Date(a.start_time));
    
    res.json({ success: true, sessions });
    
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Validate evidence integrity
router.post('/evidence/:evidenceId/validate', async (req, res) => {
  try {
    const { evidenceId } = req.params;
    const db = req.app.locals.dbConnector;
    
    // Get evidence details
    const evidence = await db.get(
      'SELECT * FROM evidence WHERE id = ?',
      [evidenceId]
    );
    
    if (!evidence) {
      return res.status(404).json({ success: false, error: 'Evidence not found' });
    }
    
    // Get file path
    const filePath = path.join(__dirname, '../../data', evidence.source);
    
    if (!(await fs.pathExists(filePath))) {
      return res.status(404).json({ success: false, error: 'Evidence file not found' });
    }
    
    // Calculate current hashes
    const currentHashes = await hashCalculator.calculateAllHashes(filePath);
    
    // Compare with stored hashes
    const integrityCheck = {
      md5: currentHashes.md5 === evidence.hash_md5,
      sha1: currentHashes.sha1 === evidence.hash_sha1,
      sha256: currentHashes.sha256 === evidence.hash_sha256,
      file_exists: true,
      size_matches: (await fs.stat(filePath)).size === evidence.size_bytes
    };
    
    const isIntegrityMaintained = Object.values(integrityCheck).every(check => check === true);
    
    // Log validation
    await db.run(
      `INSERT INTO evidence_chain (
        id, evidence_id, action, user, details
      ) VALUES (?, ?, ?, ?, ?)`,
      [
        uuidv4(), evidenceId, 'integrity_validated', 
        req.user || 'system', 
        `Integrity validation: ${isIntegrityMaintained ? 'PASSED' : 'FAILED'}`
      ]
    );
    
    res.json({ 
      success: true, 
      evidence_id: evidenceId,
      integrity_check: integrityCheck,
      is_integrity_maintained: isIntegrityMaintained,
      message: isIntegrityMaintained ? 'Evidence integrity maintained' : 'Evidence integrity compromised'
    });
    
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;
