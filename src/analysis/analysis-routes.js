const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs-extra');
const { v4: uuidv4 } = require('uuid');
const HashCalculator = require('../core/hash-calculator');

// Initialize hash calculator
const hashCalculator = new HashCalculator();

// Start new analysis
router.post('/start', async (req, res) => {
  try {
    const { evidence_id, analysis_type, analyst, tools_used, analysis_parameters } = req.body;
    
    if (!evidence_id || !analysis_type || !analyst) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing required fields: evidence_id, analysis_type, analyst' 
      });
    }
    
    const db = req.app.locals.dbConnector;
    
    // Verify evidence exists
    const evidence = await db.get(
      'SELECT * FROM evidence WHERE id = ?',
      [evidence_id]
    );
    
    if (!evidence) {
      return res.status(404).json({ success: false, error: 'Evidence not found' });
    }
    
    const analysisId = uuidv4();
    
    // Create analysis record
    await db.run(
      `INSERT INTO analysis_results (
        id, evidence_id, analysis_type, result_data, confidence_score, analyst, tools_used
      ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        analysisId, evidence_id, analysis_type, 
        JSON.stringify({ status: 'in_progress', start_time: new Date().toISOString() }),
        0.0, analyst, tools_used || 'manual'
      ]
    );
    
    // Log analysis start
    await db.run(
      `INSERT INTO evidence_chain (
        id, evidence_id, action, user, details
      ) VALUES (?, ?, ?, ?, ?)`,
      [
        uuidv4(), evidence_id, 'analysis_started', 
        analyst, 
        `Started ${analysis_type} analysis`
      ]
    );
    
    res.status(201).json({ 
      success: true, 
      analysis_id: analysisId,
      message: 'Analysis started successfully'
    });
    
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Update analysis results
router.put('/:analysisId/update', async (req, res) => {
  try {
    const { analysisId } = req.params;
    const { result_data, confidence_score, status, notes } = req.body;
    
    if (!result_data) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing required field: result_data' 
      });
    }
    
    const db = req.app.locals.dbConnector;
    
    // Get current analysis
    const analysis = await db.get(
      'SELECT * FROM analysis_results WHERE id = ?',
      [analysisId]
    );
    
    if (!analysis) {
      return res.status(404).json({ success: false, error: 'Analysis not found' });
    }
    
    // Update analysis results
    const updatedResultData = {
      ...JSON.parse(analysis.result_data || '{}'),
      ...result_data,
      last_updated: new Date().toISOString(),
      status: status || 'completed'
    };
    
    await db.run(
      `UPDATE analysis_results SET 
        result_data = ?, confidence_score = ?, analysis_date = CURRENT_TIMESTAMP
      WHERE id = ?`,
      [JSON.stringify(updatedResultData), confidence_score || 0.0, analysisId]
    );
    
    // Log analysis update
    await db.run(
      `INSERT INTO evidence_chain (
        id, evidence_id, action, user, details
      ) VALUES (?, ?, ?, ?, ?)`,
      [
        uuidv4(), analysis.evidence_id, 'analysis_updated', 
        req.user || 'system', 
        `Analysis ${analysisId} updated: ${status || 'completed'}`
      ]
    );
    
    res.json({ 
      success: true, 
      message: 'Analysis results updated successfully'
    });
    
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get analysis results
router.get('/:analysisId', async (req, res) => {
  try {
    const { analysisId } = req.params;
    const db = req.app.locals.dbConnector;
    
    const analysis = await db.get(
      'SELECT * FROM analysis_results WHERE id = ?',
      [analysisId]
    );
    
    if (!analysis) {
      return res.status(404).json({ success: false, error: 'Analysis not found' });
    }
    
    // Get evidence details
    const evidence = await db.get(
      'SELECT * FROM evidence WHERE id = ?',
      [analysis.evidence_id]
    );
    
    res.json({ 
      success: true, 
      analysis,
      evidence
    });
    
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get all analyses for evidence
router.get('/evidence/:evidenceId', async (req, res) => {
  try {
    const { evidenceId } = req.params;
    const db = req.app.locals.dbConnector;
    
    const analyses = await db.all(
      'SELECT * FROM analysis_results WHERE evidence_id = ? ORDER BY analysis_date DESC',
      [evidenceId]
    );
    
    res.json({ 
      success: true, 
      analyses
    });
    
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Perform automated file analysis
router.post('/automated/file/:evidenceId', async (req, res) => {
  try {
    const { evidenceId } = req.params;
    const { analysis_types } = req.body;
    
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
    
    const analysisResults = {};
    const analysisId = uuidv4();
    
    // Perform basic file analysis
    const stats = await fs.stat(filePath);
    const fileExtension = path.extname(filePath).toLowerCase();
    
    analysisResults.basic_info = {
      filename: path.basename(filePath),
      extension: fileExtension,
      size_bytes: stats.size,
      created: stats.birthtime,
      modified: stats.mtime,
      accessed: stats.atime
    };
    
    // Calculate hashes if not already present
    if (!evidence.hash_md5 || !evidence.hash_sha1 || !evidence.hash_sha256) {
      const hashes = await hashCalculator.calculateAllHashes(filePath);
      analysisResults.hashes = hashes;
      
      // Update evidence with hashes
      await db.run(
        `UPDATE evidence SET 
          hash_md5 = ?, hash_sha1 = ?, hash_sha256 = ?
        WHERE id = ?`,
        [hashes.md5, hashes.sha1, hashes.sha256, evidenceId]
      );
    } else {
      analysisResults.hashes = {
        md5: evidence.hash_md5,
        sha1: evidence.hash_sha1,
        sha256: evidence.hash_sha256
      };
    }
    
    // File type analysis
    analysisResults.file_type = {
      mime_type: await getMimeType(filePath),
      is_binary: await isBinaryFile(filePath),
      is_text: await isTextFile(filePath),
      is_image: fileExtension.match(/\.(jpg|jpeg|png|gif|bmp|tiff|webp)$/i) !== null,
      is_video: fileExtension.match(/\.(mp4|avi|mov|wmv|flv|mkv|webm)$/i) !== null,
      is_audio: fileExtension.match(/\.(mp3|wav|flac|aac|ogg|wma)$/i) !== null,
      is_archive: fileExtension.match(/\.(zip|rar|7z|tar|gz|bz2)$/i) !== null
    };
    
    // Store analysis results
    await db.run(
      `INSERT INTO analysis_results (
        id, evidence_id, analysis_type, result_data, confidence_score, analyst, tools_used
      ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        analysisId, evidenceId, 'automated_file_analysis', 
        JSON.stringify(analysisResults),
        0.95, 'system', 'automated_file_analyzer'
      ]
    );
    
    // Log automated analysis
    await db.run(
      `INSERT INTO evidence_chain (
        id, evidence_id, action, user, details
      ) VALUES (?, ?, ?, ?, ?)`,
      [
        uuidv4(), evidenceId, 'automated_analysis_completed', 
        'system', 
        'Automated file analysis completed'
      ]
    );
    
    res.json({ 
      success: true, 
      analysis_id: analysisId,
      results: analysisResults,
      message: 'Automated file analysis completed'
    });
    
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Helper functions
async function getMimeType(filePath) {
  // Simple MIME type detection based on file extension
  const ext = path.extname(filePath).toLowerCase();
  const mimeTypes = {
    '.txt': 'text/plain',
    '.html': 'text/html',
    '.css': 'text/css',
    '.js': 'application/javascript',
    '.json': 'application/json',
    '.xml': 'application/xml',
    '.pdf': 'application/pdf',
    '.zip': 'application/zip',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png': 'image/png',
    '.gif': 'image/gif',
    '.mp3': 'audio/mpeg',
    '.mp4': 'video/mp4'
  };
  
  return mimeTypes[ext] || 'application/octet-stream';
}

async function isBinaryFile(filePath) {
  try {
    const buffer = await fs.readFile(filePath, { encoding: null });
    const sample = buffer.slice(0, 1024);
    
    // Check for null bytes or control characters
    for (let i = 0; i < sample.length; i++) {
      if (sample[i] === 0 || (sample[i] < 32 && sample[i] !== 9 && sample[i] !== 10 && sample[i] !== 13)) {
        return true;
      }
    }
    return false;
  } catch (error) {
    return false;
  }
}

async function isTextFile(filePath) {
  try {
    const buffer = await fs.readFile(filePath, { encoding: null });
    const sample = buffer.slice(0, 1024);
    
    // Check if file contains mostly printable ASCII characters
    let printableCount = 0;
    for (let i = 0; i < sample.length; i++) {
      if (sample[i] >= 32 && sample[i] <= 126 || sample[i] === 9 || sample[i] === 10 || sample[i] === 13) {
        printableCount++;
      }
    }
    
    return (printableCount / sample.length) > 0.8;
  } catch (error) {
    return false;
  }
}

// Get analysis statistics
router.get('/stats/overview', async (req, res) => {
  try {
    const db = req.app.locals.dbConnector;
    
    // Get analysis count by type
    const analysisByType = await db.all(
      `SELECT analysis_type, COUNT(*) as count, AVG(confidence_score) as avg_confidence
       FROM analysis_results 
       GROUP BY analysis_type`
    );
    
    // Get analysis count by analyst
    const analysisByAnalyst = await db.all(
      `SELECT analyst, COUNT(*) as count
       FROM analysis_results 
       GROUP BY analyst
       ORDER BY count DESC`
    );
    
    // Get recent analyses
    const recentAnalyses = await db.all(
      `SELECT ar.*, e.name as evidence_name
       FROM analysis_results ar
       JOIN evidence e ON ar.evidence_id = e.id
       ORDER BY ar.analysis_date DESC
       LIMIT 10`
    );
    
    res.json({
      success: true,
      stats: {
        analysis_by_type: analysisByType,
        analysis_by_analyst: analysisByAnalyst,
        recent_analyses: recentAnalyses
      }
    });
    
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;
