const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');

// Get all cases
router.get('/', async (req, res) => {
  try {
    const { status, priority, investigator } = req.query;
    const db = req.app.locals.dbConnector;
    
    let sql = 'SELECT * FROM cases WHERE 1=1';
    const params = [];
    
    if (status) {
      sql += ' AND status = ?';
      params.push(status);
    }
    
    if (priority) {
      sql += ' AND priority = ?';
      params.push(priority);
    }
    
    if (investigator) {
      sql += ' AND investigator = ?';
      params.push(investigator);
    }
    
    sql += ' ORDER BY created_at DESC';
    
    const cases = await db.query(sql, params);
    
    res.json({ success: true, cases });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get specific case by ID
router.get('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const db = req.app.locals.dbConnector;
    
    const caseData = await db.queryOne(
      'SELECT * FROM cases WHERE case_id = ?',
      [id]
    );
    
    if (!caseData) {
      return res.status(404).json({ success: false, error: 'Case not found' });
    }
    
    // Get evidence count for this case
    const evidenceCount = await db.queryOne(
      'SELECT COUNT(*) as count FROM evidence WHERE evidence_id = ?',
      [id]
    );
    
    // Get recent activity
    const recentActivity = await db.query(
      `SELECT ec.*, e.name as evidence_name 
       FROM evidence_chain ec
       JOIN evidence e ON ec.evidence_id = e.evidence_id
       WHERE e.case_id = ?
       ORDER BY ec.timestamp DESC
       LIMIT 10`,
      [id]
    );
    
    res.json({ 
      success: true, 
      case: caseData,
      evidence_count: evidenceCount.count,
      recent_activity: recentActivity
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Create new case
router.post('/', async (req, res) => {
  try {
    const { case_number, title, description, investigator, priority } = req.body;
    
    if (!case_number || !title || !investigator) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing required fields: case_number, title, investigator' 
      });
    }
    
    const db = req.app.locals.dbConnector;
    const caseId = uuidv4();
    
    // Check if case number already exists
    const existingCase = await db.queryOne(
      'SELECT case_id FROM cases WHERE case_number = ?',
      [case_number]
    );
    
    if (existingCase) {
      return res.status(409).json({ 
        success: false, 
        error: 'Case number already exists' 
      });
    }
    
    // Insert new case
    await db.execute(
      `INSERT INTO cases (
        case_id, case_number, title, description, investigator, priority, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [caseId, case_number, title, description, investigator, priority || 'medium', 'open']
    );
    
    res.status(201).json({ 
      success: true, 
      case_id: caseId,
      message: 'Case created successfully'
    });
    
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Update case
router.put('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { title, description, investigator, priority, status } = req.body;
    const db = req.app.locals.dbConnector;
    
    // Check if case exists
    const existingCase = await db.queryOne(
      'SELECT * FROM cases WHERE case_id = ?',
      [id]
    );
    
    if (!existingCase) {
      return res.status(404).json({ success: false, error: 'Case not found' });
    }
    
    // Update case
    await db.execute(
      `UPDATE cases SET 
        title = COALESCE(?, title),
        description = COALESCE(?, description),
        investigator = COALESCE(?, investigator),
        priority = COALESCE(?, priority),
        status = COALESCE(?, status),
        updated_at = CURRENT_TIMESTAMP,
        closed_at = CASE WHEN ? = 'closed' THEN CURRENT_TIMESTAMP ELSE closed_at END
      WHERE case_id = ?`,
      [title, description, investigator, priority, status, status, id]
    );
    
    res.json({ success: true, message: 'Case updated successfully' });
    
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Delete case
router.delete('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const db = req.app.locals.dbConnector;
    
    // Check if case exists
    const existingCase = await db.queryOne(
      'SELECT * FROM cases WHERE case_id = ?',
      [id]
    );
    
    if (!existingCase) {
      return res.status(404).json({ success: false, error: 'Case not found' });
    }
    
    // Check if case has evidence
    const evidenceCount = await db.queryOne(
      'SELECT COUNT(*) as count FROM evidence WHERE case_id = ?',
      [id]
    );
    
    if (evidenceCount.count > 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'Cannot delete case with associated evidence. Remove evidence first.' 
      });
    }
    
    // Begin transaction
    await db.beginTransaction('delete-case-' + id);
    
    try {
      // Delete case
      await db.execute('DELETE FROM cases WHERE case_id = ?', [id]);
      
      await db.commitTransaction('delete-case-' + id);
      
      res.json({ success: true, message: 'Case deleted successfully' });
      
    } catch (error) {
      await db.rollbackTransaction('delete-case-' + id);
      throw error;
    }
    
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get case statistics
router.get('/:id/stats', async (req, res) => {
  try {
    const { id } = req.params;
    const db = req.app.locals.dbConnector;
    
    // Get evidence count by type
    const evidenceByType = await db.query(
      `SELECT type, COUNT(*) as count 
       FROM evidence 
       WHERE case_id = ? 
       GROUP BY type`,
      [id]
    );
    
    // Get evidence count by status
    const evidenceByStatus = await db.query(
      `SELECT status, COUNT(*) as count 
       FROM evidence 
       WHERE case_id = ? 
       GROUP BY status`,
      [id]
    );
    
    // Get total evidence size
    const totalSize = await db.queryOne(
      'SELECT SUM(size_bytes) as total_size FROM evidence WHERE case_id = ?',
      [id]
    );
    
    // Get analysis results count
    const analysisCount = await db.queryOne(
      `SELECT COUNT(*) as count 
       FROM analysis_results ar
       JOIN evidence e ON ar.evidence_id = e.evidence_id
       WHERE e.case_id = ?`,
      [id]
    );
    
    res.json({
      success: true,
      stats: {
        evidence_by_type: evidenceByType,
        evidence_by_status: evidenceByStatus,
        total_size_bytes: totalSize.total_size || 0,
        analysis_results_count: analysisCount.count || 0
      }
    });
    
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Search cases
router.get('/search/:query', async (req, res) => {
  try {
    const { query } = req.params;
    const db = req.app.locals.dbConnector;
    
    const searchResults = await db.query(
      `SELECT * FROM cases 
       WHERE title LIKE ? OR description LIKE ? OR case_number LIKE ? OR investigator LIKE ?
       ORDER BY created_at DESC`,
      [`%${query}%`, `%${query}%`, `%${query}%`, `%${query}%`]
    );
    
    res.json({ success: true, results: searchResults });
    
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;
