import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import './App.css';

// Components
import Dashboard from './components/Dashboard';
import CaseManagement from './components/CaseManagement';
import EvidenceManagement from './components/EvidenceManagement';
import Analysis from './components/Analysis';
import Reports from './components/Reports';
import Acquisition from './components/Acquisition';

function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [user, setUser] = useState({ name: 'Investigator', role: 'analyst' });

  return (
    <Router>
      <div className="App">
        <header className="App-header">
          <div className="header-content">
            <h1>Digital Forensics Toolkit</h1>
            <div className="user-info">
              <span>Welcome, {user.name}</span>
              <span className="role-badge">{user.role}</span>
            </div>
          </div>
        </header>

        <nav className="App-nav">
          <ul>
            <li className={activeTab === 'dashboard' ? 'active' : ''}>
              <Link to="/" onClick={() => setActiveTab('dashboard')}>
                <i className="fas fa-tachometer-alt"></i>
                Dashboard
              </Link>
            </li>
            <li className={activeTab === 'cases' ? 'active' : ''}>
              <Link to="/cases" onClick={() => setActiveTab('cases')}>
                <i className="fas fa-folder"></i>
                Cases
              </Link>
            </li>
            <li className={activeTab === 'evidence' ? 'active' : ''}>
              <Link to="/evidence" onClick={() => setActiveTab('evidence')}>
                <i className="fas fa-microscope"></i>
                Evidence
              </Link>
            </li>
            <li className={activeTab === 'acquisition' ? 'active' : ''}>
              <Link to="/acquisition" onClick={() => setActiveTab('acquisition')}>
                <i className="fas fa-download"></i>
                Acquisition
              </Link>
            </li>
            <li className={activeTab === 'analysis' ? 'active' : ''}>
              <Link to="/analysis" onClick={() => setActiveTab('analysis')}>
                <i className="fas fa-search"></i>
                Analysis
              </Link>
            </li>
            <li className={activeTab === 'reports' ? 'active' : ''}>
              <Link to="/reports" onClick={() => setActiveTab('reports')}>
                <i className="fas fa-file-alt"></i>
                Reports
              </Link>
            </li>
          </ul>
        </nav>

        <main className="App-main">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/cases" element={<CaseManagement />} />
            <Route path="/evidence" element={<EvidenceManagement />} />
            <Route path="/acquisition" element={<Acquisition />} />
            <Route path="/analysis" element={<Analysis />} />
            <Route path="/reports" element={<Reports />} />
          </Routes>
        </main>

        <footer className="App-footer">
          <p>&copy; 2024 Digital Forensics Toolkit. All rights reserved.</p>
        </footer>
      </div>
    </Router>
  );
}

export default App;
