import React, { useState } from 'react';

function Reports() {
  const [reportType, setReportType] = useState('case_summary');
  const [selectedCase, setSelectedCase] = useState('');
  const [reportFormat, setReportFormat] = useState('pdf');
  const [generating, setGenerating] = useState(false);

  const generateReport = () => {
    if (!selectedCase) {
      alert('Please select a case for the report');
      return;
    }

    setGenerating(true);
    // Simulate report generation
    setTimeout(() => {
      setGenerating(false);
      alert('Report generated successfully!');
    }, 2000);
  };

  return (
    <div className="reports">
      <h2>Report Generation</h2>
      
      <div className="report-form">
        <div className="form-group">
          <label>Report Type:</label>
          <select value={reportType} onChange={(e) => setReportType(e.target.value)}>
            <option value="case_summary">Case Summary</option>
            <option value="evidence_analysis">Evidence Analysis</option>
            <option value="timeline_report">Timeline Report</option>
            <option value="chain_of_custody">Chain of Custody</option>
            <option value="comprehensive">Comprehensive Report</option>
          </select>
        </div>

        <div className="form-group">
          <label>Select Case:</label>
          <select value={selectedCase} onChange={(e) => setSelectedCase(e.target.value)}>
            <option value="">Choose a case</option>
            <option value="case1">Case 1</option>
            <option value="case2">Case 2</option>
          </select>
        </div>

        <div className="form-group">
          <label>Report Format:</label>
          <select value={reportFormat} onChange={(e) => setReportFormat(e.target.value)}>
            <option value="pdf">PDF</option>
            <option value="html">HTML</option>
            <option value="docx">Word Document</option>
            <option value="json">JSON</option>
          </select>
        </div>

        <button 
          className="btn btn-primary" 
          onClick={generateReport}
          disabled={generating}
        >
          {generating ? 'Generating Report...' : 'Generate Report'}
        </button>
      </div>

      <div className="report-templates">
        <h3>Report Templates</h3>
        <div className="templates-grid">
          <div className="template-card">
            <h4>Case Summary</h4>
            <p>Brief overview of case details and findings</p>
            <button className="btn btn-small">Use Template</button>
          </div>
          <div className="template-card">
            <h4>Evidence Analysis</h4>
            <p>Detailed analysis of collected evidence</p>
            <button className="btn btn-small">Use Template</button>
          </div>
          <div className="template-card">
            <h4>Timeline Report</h4>
            <p>Chronological sequence of events</p>
            <button className="btn btn-small">Use Template</button>
          </div>
          <div className="template-card">
            <h4>Chain of Custody</h4>
            <p>Evidence handling and transfer documentation</p>
            <button className="btn btn-small">Use Template</button>
          </div>
        </div>
      </div>

      <div className="report-history">
        <h3>Recent Reports</h3>
        <div className="reports-list">
          <div className="report-item">
            <span>Case Summary - Case 1</span>
            <span>Generated: 2 hours ago</span>
            <button className="btn btn-small">Download</button>
          </div>
          <div className="report-item">
            <span>Evidence Analysis - Case 2</span>
            <span>Generated: 1 day ago</span>
            <button className="btn btn-small">Download</button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Reports;

