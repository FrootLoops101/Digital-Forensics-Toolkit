import React, { useState, useEffect } from 'react';

function EvidenceManagement() {
  const [evidence, setEvidence] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchEvidence();
  }, []);

  const fetchEvidence = async () => {
    try {
      const response = await fetch('/api/evidence/case/test');
      const data = await response.json();
      if (data.success) {
        setEvidence(data.evidence);
      }
    } catch (error) {
      console.error('Error fetching evidence:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="loading">Loading evidence...</div>;
  }

  return (
    <div className="evidence-management">
      <h2>Evidence Management</h2>
      
      <div className="evidence-actions">
        <button className="btn btn-primary">Upload Evidence</button>
        <button className="btn btn-secondary">Bulk Import</button>
        <button className="btn btn-secondary">Scan Directory</button>
      </div>

      <div className="evidence-list">
        {evidence.length === 0 ? (
          <div className="no-evidence">
            <p>No evidence found. Upload evidence to get started.</p>
          </div>
        ) : (
          evidence.map(item => (
            <div key={item.evidence_id} className="evidence-card">
              <h3>{item.name}</h3>
              <p><strong>Type:</strong> {item.type}</p>
              <p><strong>Status:</strong> {item.status}</p>
              <p><strong>Size:</strong> {item.file_size ? `${(item.file_size / 1024 / 1024).toFixed(2)} MB` : 'N/A'}</p>
              <div className="evidence-actions">
                <button className="btn btn-small">View</button>
                <button className="btn btn-small">Analyze</button>
                <button className="btn btn-small btn-danger">Delete</button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

export default EvidenceManagement;

