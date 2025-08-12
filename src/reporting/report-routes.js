const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs-extra');
const PDFDocument = require('pdf-lib').PDFDocument;
const ExcelJS = require('exceljs');

// Generate comprehensive case report
router.post('/generate/case/:caseId', async (req, res) => {
  try {
    const { caseId } = req.params;
    const { report_format, include_evidence, include_analysis, include_chain_of_custody } = req.body;
    
    const db = req.app.locals.dbConnector;
    
    // Get case details
    const caseData = await db.get(
      'SELECT * FROM cases WHERE id = ?',
      [caseId]
    );
    
    if (!caseData) {
      return res.status(404).json({ success: false, error: 'Case not found' });
    }
    
    // Get evidence for this case
    const evidence = await db.all(
      'SELECT * FROM evidence WHERE case_id = ? ORDER BY acquisition_date ASC',
      [caseId]
    );
    
    // Get analysis results
    const analyses = await db.all(
      `SELECT ar.*, e.name as evidence_name
       FROM analysis_results ar
       JOIN evidence e ON ar.evidence_id = e.id
       WHERE e.case_id = ?
       ORDER BY ar.analysis_date DESC`,
      [caseId]
    );
    
    // Get chain of custody
    const chainOfCustody = await db.all(
      `SELECT ec.*, e.name as evidence_name
       FROM evidence_chain ec
       JOIN evidence e ON ec.evidence_id = e.id
       WHERE e.case_id = ?
       ORDER BY ec.timestamp ASC`,
      [caseId]
    );
    
    // Generate report content
    const reportContent = generateReportContent(caseData, evidence, analyses, chainOfCustody);
    
    const reportId = uuidv4();
    const reportTitle = `Case Report - ${caseData.case_number} - ${caseData.title}`;
    
    // Store report in database
    await db.run(
      `INSERT INTO reports (
        id, case_id, title, content, format, generated_by, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        reportId, caseId, reportTitle, JSON.stringify(reportContent),
        report_format || 'pdf', req.user || 'system', 'completed'
      ]
    );
    
    // Generate file based on format
    let reportFile = null;
    if (report_format === 'excel') {
      reportFile = await generateExcelReport(reportContent, reportTitle);
    } else {
      reportFile = await generatePDFReport(reportContent, reportTitle);
    }
    
    // Save report file
    const reportDir = path.join(__dirname, '../../data/reports', caseId);
    await fs.ensureDir(reportDir);
    const reportPath = path.join(reportDir, `${reportId}.${report_format || 'pdf'}`);
    await fs.writeFile(reportPath, reportFile);
    
    res.json({ 
      success: true, 
      report_id: reportId,
      report_path: reportPath,
      message: 'Report generated successfully'
    });
    
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Generate evidence-specific report
router.post('/generate/evidence/:evidenceId', async (req, res) => {
  try {
    const { evidenceId } = req.params;
    const { report_format } = req.body;
    
    const db = req.app.locals.dbConnector;
    
    // Get evidence details
    const evidence = await db.get(
      'SELECT * FROM evidence WHERE id = ?',
      [evidenceId]
    );
    
    if (!evidence) {
      return res.status(404).json({ success: false, error: 'Evidence not found' });
    }
    
    // Get case details
    const caseData = await db.get(
      'SELECT * FROM cases WHERE id = ?',
      [evidence.case_id]
    );
    
    // Get analysis results for this evidence
    const analyses = await db.all(
      'SELECT * FROM analysis_results WHERE evidence_id = ? ORDER BY analysis_date DESC',
      [evidenceId]
    );
    
    // Get chain of custody for this evidence
    const chainOfCustody = await db.all(
      'SELECT * FROM evidence_chain WHERE evidence_id = ? ORDER BY timestamp ASC',
      [evidenceId]
    );
    
    // Generate evidence report content
    const reportContent = generateEvidenceReportContent(evidence, caseData, analyses, chainOfCustody);
    
    const reportId = uuidv4();
    const reportTitle = `Evidence Report - ${evidence.name} - Case ${caseData.case_number}`;
    
    // Store report in database
    await db.run(
      `INSERT INTO reports (
        id, case_id, title, content, format, generated_by, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        reportId, evidence.case_id, reportTitle, JSON.stringify(reportContent),
        report_format || 'pdf', req.user || 'system', 'completed'
      ]
    );
    
    // Generate file
    let reportFile = null;
    if (report_format === 'excel') {
      reportFile = await generateExcelReport(reportContent, reportTitle);
    } else {
      reportFile = await generatePDFReport(reportContent, reportTitle);
    }
    
    // Save report file
    const reportDir = path.join(__dirname, '../../data/reports', evidence.case_id);
    await fs.ensureDir(reportDir);
    const reportPath = path.join(reportDir, `evidence_${reportId}.${report_format || 'pdf'}`);
    await fs.writeFile(reportPath, reportFile);
    
    res.json({ 
      success: true, 
      report_id: reportId,
      report_path: reportPath,
      message: 'Evidence report generated successfully'
    });
    
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get all reports for a case
router.get('/case/:caseId', async (req, res) => {
  try {
    const { caseId } = req.params;
    const db = req.app.locals.dbConnector;
    
    const reports = await db.all(
      'SELECT * FROM reports WHERE case_id = ? ORDER BY generated_date DESC',
      [caseId]
    );
    
    res.json({ success: true, reports });
    
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get specific report
router.get('/:reportId', async (req, res) => {
  try {
    const { reportId } = req.params;
    const db = req.app.locals.dbConnector;
    
    const report = await db.get(
      'SELECT * FROM reports WHERE id = ?',
      [reportId]
    );
    
    if (!report) {
      return res.status(404).json({ success: false, error: 'Report not found' });
    }
    
    // Get case details
    const caseData = await db.get(
      'SELECT * FROM cases WHERE id = ?',
      [report.case_id]
    );
    
    res.json({ 
      success: true, 
      report,
      case: caseData
    });
    
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Download report file
router.get('/:reportId/download', async (req, res) => {
  try {
    const { reportId } = req.params;
    const db = req.app.locals.dbConnector;
    
    const report = await db.get(
      'SELECT * FROM reports WHERE id = ?',
      [reportId]
    );
    
    if (!report) {
      return res.status(404).json({ success: false, error: 'Report not found' });
    }
    
    // Get case details
    const caseData = await db.get(
      'SELECT * FROM cases WHERE id = ?',
      [report.case_id]
    );
    
    // Construct file path
    const reportDir = path.join(__dirname, '../../data/reports', caseData.id);
    const reportPath = path.join(reportDir, `${reportId}.${report.format}`);
    
    if (!(await fs.pathExists(reportPath))) {
      return res.status(404).json({ success: false, error: 'Report file not found' });
    }
    
    // Set headers for download
    const fileName = `${report.title.replace(/[^a-z0-9]/gi, '_')}.${report.format}`;
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    res.setHeader('Content-Type', getContentType(report.format));
    
    // Stream the file
    const fileStream = fs.createReadStream(reportPath);
    fileStream.pipe(res);
    
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Helper functions
function generateReportContent(caseData, evidence, analyses, chainOfCustody) {
  return {
    case_information: {
      case_number: caseData.case_number,
      title: caseData.title,
      description: caseData.description,
      investigator: caseData.investigator,
      status: caseData.status,
      priority: caseData.priority,
      created: caseData.created_at,
      updated: caseData.updated_at,
      closed: caseData.closed_at
    },
    evidence_summary: {
      total_count: evidence.length,
      by_type: evidence.reduce((acc, e) => {
        acc[e.type] = (acc[e.type] || 0) + 1;
        return acc;
      }, {}),
      total_size_bytes: evidence.reduce((sum, e) => sum + (e.size_bytes || 0), 0),
      evidence_items: evidence.map(e => ({
        id: e.id,
        name: e.name,
        type: e.type,
        size_bytes: e.size_bytes,
        acquisition_date: e.acquisition_date,
        status: e.status
      }))
    },
    analysis_summary: {
      total_analyses: analyses.length,
      by_type: analyses.reduce((acc, a) => {
        acc[a.analysis_type] = (acc[a.analysis_type] || 0) + 1;
        return acc;
      }, {}),
      by_analyst: analyses.reduce((acc, a) => {
        acc[a.analyst] = (acc[a.analyst] || 0) + 1;
        return acc;
      }, {}),
      analyses: analyses.map(a => ({
        id: a.id,
        type: a.analysis_type,
        analyst: a.analyst,
        date: a.analysis_date,
        confidence: a.confidence_score,
        tools: a.tools_used
      }))
    },
    chain_of_custody: {
      total_events: chainOfCustody.length,
      events: chainOfCustody.map(c => ({
        timestamp: c.timestamp,
        action: c.action,
        user: c.user,
        evidence: c.evidence_name,
        details: c.details
      }))
    },
    report_metadata: {
      generated_at: new Date().toISOString(),
      generated_by: 'Digital Forensics Toolkit',
      version: '1.0.0'
    }
  };
}

function generateEvidenceReportContent(evidence, caseData, analyses, chainOfCustody) {
  return {
    case_information: {
      case_number: caseData.case_number,
      title: caseData.title,
      investigator: caseData.investigator
    },
    evidence_details: {
      id: evidence.id,
      name: evidence.name,
      type: evidence.type,
      source: evidence.source,
      size_bytes: evidence.size_bytes,
      acquisition_date: evidence.acquisition_date,
      status: evidence.status,
      notes: evidence.notes,
      hashes: {
        md5: evidence.hash_md5,
        sha1: evidence.hash_sha1,
        sha256: evidence.hash_sha256
      }
    },
    analysis_results: analyses.map(a => ({
      id: a.id,
      type: a.analysis_type,
      analyst: a.analyst,
      date: a.analysis_date,
      confidence: a.confidence_score,
      tools: a.tools_used,
      results: JSON.parse(a.result_data || '{}')
    })),
    chain_of_custody: chainOfCustody.map(c => ({
      timestamp: c.timestamp,
      action: c.action,
      user: c.user,
      details: c.details,
      hash_before: c.hash_before,
      hash_after: c.hash_after
    })),
    report_metadata: {
      generated_at: new Date().toISOString(),
      generated_by: 'Digital Forensics Toolkit',
      version: '1.0.0'
    }
  };
}

async function generatePDFReport(content, title) {
  const doc = await PDFDocument.create();
  const page = doc.addPage();
  const { width, height } = page.getSize();
  
  // Add title
  page.drawText(title, {
    x: 50,
    y: height - 50,
    size: 18,
    color: { r: 0, g: 0, b: 0 }
  });
  
  // Add content sections
  let yPosition = height - 100;
  
  for (const [section, data] of Object.entries(content)) {
    if (yPosition < 100) {
      page = doc.addPage();
      yPosition = height - 50;
    }
    
    // Section header
    page.drawText(section.replace(/_/g, ' ').toUpperCase(), {
      x: 50,
      y: yPosition,
      size: 14,
      color: { r: 0.2, g: 0.2, b: 0.8 }
    });
    yPosition -= 25;
    
    // Section content
    const contentText = JSON.stringify(data, null, 2);
    const lines = contentText.split('\n');
    
    for (const line of lines) {
      if (yPosition < 100) {
        page = doc.addPage();
        yPosition = height - 50;
      }
      
      page.drawText(line, {
        x: 70,
        y: yPosition,
        size: 10,
        color: { r: 0, g: 0, b: 0 }
      });
      yPosition -= 15;
    }
    
    yPosition -= 20;
  }
  
  return await doc.save();
}

async function generateExcelReport(content, title) {
  const workbook = new ExcelJS.Workbook();
  const worksheet = workbook.addWorksheet('Forensic Report');
  
  // Add title
  worksheet.mergeCells('A1:D1');
  worksheet.getCell('A1').value = title;
  worksheet.getCell('A1').font = { bold: true, size: 16 };
  worksheet.getCell('A1').alignment = { horizontal: 'center' };
  
  let row = 3;
  
  for (const [section, data] of Object.entries(content)) {
    // Section header
    worksheet.getCell(`A${row}`).value = section.replace(/_/g, ' ').toUpperCase();
    worksheet.getCell(`A${row}`).font = { bold: true, size: 14 };
    worksheet.getCell(`A${row}`).fill = {
      type: 'pattern',
      pattern: 'solid',
      fgColor: { argb: 'FFE0E0E0' }
    };
    row++;
    
    // Add section data
    if (typeof data === 'object' && data !== null) {
      for (const [key, value] of Object.entries(data)) {
        worksheet.getCell(`A${row}`).value = key.replace(/_/g, ' ');
        worksheet.getCell(`B${row}`).value = typeof value === 'object' ? JSON.stringify(value) : value;
        row++;
      }
    } else {
      worksheet.getCell(`A${row}`).value = data;
      row++;
    }
    
    row += 2; // Add spacing between sections
  }
  
  // Auto-fit columns
  worksheet.columns.forEach(column => {
    column.width = Math.max(
      column.width || 0,
      Math.max(...column.values.map(v => v ? v.toString().length : 0))
    );
  });
  
  return await workbook.xlsx.writeBuffer();
}

function getContentType(format) {
  const contentTypes = {
    'pdf': 'application/pdf',
    'excel': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
  };
  
  return contentTypes[format] || 'application/octet-stream';
}

module.exports = router;
