import React, { useState, useEffect } from 'react';

function Dashboard() {
  const [stats, setStats] = useState({
    cases: 0,
    evidence: 0,
    status: 'loading'
  });

  useEffect(() => {
    fetchStats();
  }, []);

  const fetchStats = async () => {
    try {
      const [casesRes, evidenceRes] = await Promise.all([
        fetch('/api/cases'),
        fetch('/api/evidence/case/test')
      ]);
      
      const casesData = await casesRes.json();
      const evidenceData = await evidenceRes.json();
      
      setStats({
        cases: casesData.success ? casesData.cases.length : 0,
        evidence: evidenceData.success ? evidenceData.evidence.length : 0,
        status: 'loaded'
      });
    } catch (error) {
      setStats({ ...stats, status: 'error' });
    }
  };

  return (
    <div className="dashboard">
      <h2>Dashboard</h2>
      <div className="stats-grid">
        <div className="stat-card">
          <h3>Total Cases</h3>
          <p className="stat-number">{stats.cases}</p>
        </div>
        <div className="stat-card">
          <h3>Total Evidence</h3>
          <p className="stat-number">{stats.evidence}</p>
        </div>
        <div className="stat-card">
          <h3>System Status</h3>
          <p className="stat-status">🟢 Operational</p>
        </div>
      </div>
      
      <div className="quick-actions">
        <h3>Quick Actions</h3>
        <div className="action-buttons">
          <button className="btn btn-primary">Create New Case</button>
          <button className="btn btn-secondary">Upload Evidence</button>
          <button className="btn btn-secondary">Generate Report</button>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;

