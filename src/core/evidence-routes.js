const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs-extra');
const { v4: uuidv4 } = require('uuid');

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const caseId = req.body.case_id || 'default';
    const uploadPath = path.join(__dirname, '../../data/uploads', caseId);
    fs.mkdirpSync(uploadPath);
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${uuidv4()}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB limit
  fileFilter: (req, file, cb) => {
    // Allow common forensic file types
    const allowedTypes = [
      'image/', 'video/', 'audio/', 'text/', 'application/',
      'application/pdf', 'application/zip', 'application/x-rar-compressed'
    ];
    
    if (allowedTypes.some(type => file.mimetype.startsWith(type))) {
      cb(null, true);
    } else {
      cb(new Error('File type not allowed'), false);
    }
  }
});

// Get all evidence for a case
router.get('/case/:caseId', async (req, res) => {
  try {
    const { caseId } = req.params;
    const db = req.app.locals.dbConnector;
    
    const evidence = await db.query(
      'SELECT * FROM evidence WHERE case_id = ? ORDER BY acquired_at DESC',
      [caseId]
    );
    
    res.json({ success: true, evidence });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get specific evidence by ID
router.get('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const db = req.app.locals.dbConnector;
    
    const evidence = await db.queryOne(
      'SELECT * FROM evidence WHERE evidence_id = ?',
      [id]
    );
    
    if (!evidence) {
      return res.status(404).json({ success: false, error: 'Evidence not found' });
    }
    
    res.json({ success: true, evidence });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Upload new evidence
router.post('/upload', upload.single('evidence_file'), async (req, res) => {
  try {
    const { case_id, name, type, source, notes } = req.body;
    const file = req.file;
    
    if (!file) {
      return res.status(400).json({ success: false, error: 'No file uploaded' });
    }
    
    if (!case_id || !name || !type || !source) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing required fields: case_id, name, type, source' 
      });
    }
    
    const db = req.app.locals.dbConnector;
    const evidenceId = uuidv4();
    
    // Get file stats
    const stats = await fs.stat(file.path);
    
    // Insert evidence record
    await db.execute(
      `INSERT INTO evidence (
        evidence_id, case_id, name, type, source, size_bytes, notes, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [evidenceId, case_id, name, type, source, stats.size, notes, 'acquired']
    );
    
    // Log the acquisition
    await db.execute(
      `INSERT INTO evidence_chain (
        chain_id, evidence_id, action, user, details
      ) VALUES (?, ?, ?, ?, ?)`,
      [uuidv4(), evidenceId, 'acquired', req.user || 'system', 'Evidence file uploaded']
    );
    
    res.json({ 
      success: true, 
      evidence_id: evidenceId,
      message: 'Evidence uploaded successfully'
    });
    
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Update evidence information
router.put('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { name, type, source, notes, status } = req.body;
    const db = req.app.locals.dbConnector;
    
    // Get current evidence
    const currentEvidence = await db.queryOne(
      'SELECT * FROM evidence WHERE evidence_id = ?',
      [id]
    );
    
    if (!currentEvidence) {
      return res.status(404).json({ success: false, error: 'Evidence not found' });
    }
    
    // Update evidence
    await db.execute(
      `UPDATE evidence SET 
        name = COALESCE(?, name),
        type = COALESCE(?, type),
        source = COALESCE(?, source),
        notes = COALESCE(?, notes),
        status = COALESCE(?, status),
        updated_at = CURRENT_TIMESTAMP
      WHERE evidence_id = ?`,
      [name, type, source, notes, status, id]
    );
    
    // Log the update
    await db.execute(
      `INSERT INTO evidence_chain (
        chain_id, evidence_id, action, user, details
      ) VALUES (?, ?, ?, ?, ?)`,
      [uuidv4(), id, 'updated', req.user || 'system', 'Evidence information updated']
    );
    
    res.json({ success: true, message: 'Evidence updated successfully' });
    
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Delete evidence
router.delete('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const db = req.app.locals.dbConnector;
    
    // Get evidence details for file cleanup
    const evidence = await db.queryOne(
      'SELECT * FROM evidence WHERE evidence_id = ?',
      [id]
    );
    
    if (!evidence) {
      return res.status(404).json({ success: false, error: 'Evidence not found' });
    }
    
    // Begin transaction
    await db.beginTransaction('delete-evidence-' + id);
    
    try {
      // Delete evidence chain records
      await db.execute('DELETE FROM evidence_chain WHERE evidence_id = ?', [id]);
      
      // Delete analysis results
      await db.execute('DELETE FROM analysis_results WHERE evidence_id = ?', [id]);
      
      // Delete evidence record
      await db.execute('DELETE FROM evidence WHERE evidence_id = ?', [id]);
      
      // Clean up uploaded file if it exists
      if (evidence.source && evidence.source.startsWith('uploads/')) {
        const filePath = path.join(__dirname, '../../data', evidence.source);
        if (await fs.pathExists(filePath)) {
          await fs.remove(filePath);
        }
      }
      
      await db.commitTransaction('delete-evidence-' + id);
      
      res.json({ success: true, message: 'Evidence deleted successfully' });
      
    } catch (error) {
      await db.rollbackTransaction('delete-evidence-' + id);
      throw error;
    }
    
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get evidence chain of custody
router.get('/:id/chain', async (req, res) => {
  try {
    const { id } = req.params;
    const db = req.app.locals.dbConnector;
    
    const chain = await db.query(
      `SELECT * FROM evidence_chain 
       WHERE evidence_id = ? 
       ORDER BY timestamp ASC`,
      [id]
    );
    
    res.json({ success: true, chain });
    
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;
