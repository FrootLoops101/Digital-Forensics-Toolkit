import React, { useState } from 'react';

function Analysis() {
  const [selectedEvidence, setSelectedEvidence] = useState('');
  const [analysisType, setAnalysisType] = useState('file_carving');
  const [analysisStatus, setAnalysisStatus] = useState('idle');

  const startAnalysis = () => {
    if (!selectedEvidence) {
      alert('Please select evidence to analyze');
      return;
    }

    setAnalysisStatus('running');
    // Simulate analysis process
    setTimeout(() => {
      setAnalysisStatus('completed');
    }, 3000);
  };

  return (
    <div className="analysis">
      <h2>Forensic Analysis</h2>
      
      <div className="analysis-form">
        <div className="form-group">
          <label>Select Evidence:</label>
          <select value={selectedEvidence} onChange={(e) => setSelectedEvidence(e.target.value)}>
            <option value="">Choose evidence to analyze</option>
            <option value="evidence1">Evidence 1</option>
            <option value="evidence2">Evidence 2</option>
          </select>
        </div>

        <div className="form-group">
          <label>Analysis Type:</label>
          <select value={analysisType} onChange={(e) => setAnalysisType(e.target.value)}>
            <option value="file_carving">File Carving</option>
            <option value="keyword_search">Keyword Search</option>
            <option value="timeline">Timeline Analysis</option>
            <option value="hash_analysis">Hash Analysis</option>
            <option value="metadata">Metadata Extraction</option>
          </select>
        </div>

        <button 
          className="btn btn-primary" 
          onClick={startAnalysis}
          disabled={analysisStatus === 'running'}
        >
          {analysisStatus === 'running' ? 'Analyzing...' : 'Start Analysis'}
        </button>
      </div>

      {analysisStatus === 'running' && (
        <div className="analysis-progress">
          <h3>Analysis in Progress</h3>
          <div className="progress-bar">
            <div className="progress-fill" style={{ width: '60%' }}></div>
          </div>
          <p>Processing evidence...</p>
        </div>
      )}

      {analysisStatus === 'completed' && (
        <div className="analysis-results">
          <h3>Analysis Results</h3>
          <div className="results-summary">
            <p><strong>Files Found:</strong> 15</p>
            <p><strong>Keywords Matched:</strong> 8</p>
            <p><strong>Timeline Events:</strong> 127</p>
            <p><strong>Analysis Duration:</strong> 3.2 seconds</p>
          </div>
          <button className="btn btn-secondary">Export Results</button>
          <button className="btn btn-secondary">Generate Report</button>
        </div>
      )}

      <div className="analysis-tools">
        <h3>Available Analysis Tools</h3>
        <div className="tools-grid">
          <div className="tool-card">
            <h4>File Carving</h4>
            <p>Recover deleted files and fragments</p>
          </div>
          <div className="tool-card">
            <h4>Keyword Search</h4>
            <p>Search for specific terms and patterns</p>
          </div>
          <div className="tool-card">
            <h4>Timeline Analysis</h4>
            <p>Create chronological event timeline</p>
          </div>
          <div className="tool-card">
            <h4>Hash Analysis</h4>
            <p>Calculate and verify file hashes</p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Analysis;

