import React, { useState } from 'react';

function Acquisition() {
  const [acquisitionType, setAcquisitionType] = useState('disk');
  const [target, setTarget] = useState('');
  const [progress, setProgress] = useState(0);

  const startAcquisition = () => {
    setProgress(0);
    // Simulate acquisition progress
    const interval = setInterval(() => {
      setProgress(prev => {
        if (prev >= 100) {
          clearInterval(interval);
          return 100;
        }
        return prev + 10;
      });
    }, 500);
  };

  return (
    <div className="acquisition">
      <h2>Digital Evidence Acquisition</h2>
      
      <div className="acquisition-form">
        <div className="form-group">
          <label>Acquisition Type:</label>
          <select value={acquisitionType} onChange={(e) => setAcquisitionType(e.target.value)}>
            <option value="disk">Disk Imaging</option>
            <option value="memory">Memory Dump</option>
            <option value="network">Network Capture</option>
            <option value="file">File Acquisition</option>
          </select>
        </div>

        <div className="form-group">
          <label>Target:</label>
          <input 
            type="text" 
            value={target} 
            onChange={(e) => setTarget(e.target.value)}
            placeholder="Enter target path or device"
          />
        </div>

        <button className="btn btn-primary" onClick={startAcquisition}>
          Start Acquisition
        </button>
      </div>

      {progress > 0 && (
        <div className="acquisition-progress">
          <h3>Acquisition Progress</h3>
          <div className="progress-bar">
            <div className="progress-fill" style={{ width: `${progress}%` }}></div>
          </div>
          <p>{progress}% Complete</p>
        </div>
      )}

      <div className="acquisition-info">
        <h3>Acquisition Guidelines</h3>
        <ul>
          <li>Always verify the integrity of acquired evidence</li>
          <li>Document the acquisition process thoroughly</li>
          <li>Use write-blocking devices when possible</li>
          <li>Calculate hash values for verification</li>
        </ul>
      </div>
    </div>
  );
}

export default Acquisition;

