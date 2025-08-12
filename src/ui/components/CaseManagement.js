import React, { useState, useEffect } from 'react';

function CaseManagement() {
  const [cases, setCases] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchCases();
  }, []);

  const fetchCases = async () => {
    try {
      const response = await fetch('/api/cases');
      const data = await response.json();
      if (data.success) {
        setCases(data.cases);
      }
    } catch (error) {
      console.error('Error fetching cases:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="loading">Loading cases...</div>;
  }

  return (
    <div className="case-management">
      <h2>Case Management</h2>
      
      <div className="case-actions">
        <button className="btn btn-primary">Create New Case</button>
        <button className="btn btn-secondary">Import Cases</button>
      </div>

      <div className="cases-list">
        {cases.length === 0 ? (
          <div className="no-cases">
            <p>No cases found. Create your first case to get started.</p>
          </div>
        ) : (
          cases.map(caseItem => (
            <div key={caseItem.case_id} className="case-card">
              <h3>{caseItem.title}</h3>
              <p><strong>Case Number:</strong> {caseItem.case_number}</p>
              <p><strong>Status:</strong> {caseItem.status}</p>
              <p><strong>Priority:</strong> {caseItem.priority}</p>
              <div className="case-actions">
                <button className="btn btn-small">View</button>
                <button className="btn btn-small">Edit</button>
                <button className="btn btn-small btn-danger">Delete</button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

export default CaseManagement;

