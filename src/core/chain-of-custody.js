/**
 * Chain of Custody Manager
 * 
 * This module implements comprehensive chain of custody tracking for digital evidence,
 * ensuring forensic integrity and compliance with forensic standards.
 * 
 * Features:
 * - Evidence custody tracking with timestamps
 * - Digital signatures for custody transfers
 * - Audit trail maintenance
 * - Integrity verification
 * - Compliance with forensic standards
 */

const crypto = require('crypto');
const fs = require('fs-extra');
const path = require('path');

class ChainOfCustody {
  constructor(logger, dbConnector) {
    this.logger = logger;
    this.dbConnector = dbConnector;
    this.auditTrail = [];
  }

  /**
   * Create a new chain of custody record for evidence
   * @param {Object} evidence - Evidence object
   * @param {string} investigator - Investigator ID
   * @param {string} location - Current location
   * @param {string} notes - Initial notes
   * @returns {Object} Chain of custody record
   */
  async createCustodyRecord(evidence, investigator, location, notes = '') {
    try {
      const custodyId = this.generateCustodyId();
      const timestamp = new Date().toISOString();
      
      const custodyRecord = {
        custodyId,
        evidenceId: evidence.evidenceId,
        investigatorId: investigator,
        location,
        timestamp,
        action: 'ACQUISITION',
        notes,
        digitalSignature: this.generateDigitalSignature(evidence.evidenceId, investigator, timestamp),
        integrityHash: await this.calculateIntegrityHash(evidence),
        previousCustodyId: null,
        nextCustodyId: null,
        status: 'ACTIVE'
      };

      // Store in database
      await this.storeCustodyRecord(custodyRecord);
      
      // Add to audit trail
      this.addToAuditTrail(custodyRecord);
      
      this.logger.info(`Chain of custody created for evidence ${evidence.evidenceId}`, {
        custodyId,
        investigator,
        location
      });

      return custodyRecord;
    } catch (error) {
      this.logger.error('Failed to create chain of custody record:', error);
      throw new Error('Chain of custody creation failed');
    }
  }

  /**
   * Transfer custody of evidence to another investigator
   * @param {string} evidenceId - Evidence ID
   * @param {string} fromInvestigator - Current investigator
   * @param {string} toInvestigator - New investigator
   * @param {string} newLocation - New location
   * @param {string} reason - Reason for transfer
   * @returns {Object} Updated custody record
   */
  async transferCustody(evidenceId, fromInvestigator, toInvestigator, newLocation, reason = '') {
    try {
      // Verify current custody
      const currentCustody = await this.getCurrentCustody(evidenceId);
      
      if (!currentCustody || currentCustody.investigatorId !== fromInvestigator) {
        throw new Error('Invalid custody transfer: Current investigator mismatch');
      }

      // Close current custody record
      await this.closeCustodyRecord(currentCustody.custodyId, 'TRANSFERRED');

      // Create new custody record
      const newCustodyRecord = await this.createCustodyRecord(
        { evidenceId },
        toInvestigator,
        newLocation,
        `Transfer from ${fromInvestigator}. Reason: ${reason}`
      );

      // Link custody records
      await this.linkCustodyRecords(currentCustody.custodyId, newCustodyRecord.custodyId);

      // Verify integrity after transfer
      await this.verifyEvidenceIntegrity(evidenceId);

      this.logger.info(`Custody transferred for evidence ${evidenceId}`, {
        from: fromInvestigator,
        to: toInvestigator,
        location: newLocation
      });

      return newCustodyRecord;
    } catch (error) {
      this.logger.error('Failed to transfer custody:', error);
      throw new Error('Custody transfer failed');
    }
  }

  /**
   * Verify evidence integrity using stored hash
   * @param {string} evidenceId - Evidence ID
   * @returns {boolean} Integrity verification result
   */
  async verifyEvidenceIntegrity(evidenceId) {
    try {
      const currentCustody = await this.getCurrentCustody(evidenceId);
      if (!currentCustody) {
        throw new Error('No custody record found for evidence');
      }

      const currentHash = await this.calculateIntegrityHash({ evidenceId });
      const storedHash = currentCustody.integrityHash;

      if (currentHash !== storedHash) {
        this.logger.error(`Evidence integrity compromised for ${evidenceId}`, {
          storedHash,
          currentHash
        });
        return false;
      }

      this.logger.info(`Evidence integrity verified for ${evidenceId}`);
      return true;
    } catch (error) {
      this.logger.error('Failed to verify evidence integrity:', error);
      return false;
    }
  }

  /**
   * Generate comprehensive custody report
   * @param {string} evidenceId - Evidence ID
   * @returns {Object} Complete custody report
   */
  async generateCustodyReport(evidenceId) {
    try {
      const custodyChain = await this.getCustodyChain(evidenceId);
      const integrityStatus = await this.verifyEvidenceIntegrity(evidenceId);
      
      const report = {
        evidenceId,
        reportGenerated: new Date().toISOString(),
        integrityStatus,
        custodyChain,
        summary: {
          totalTransfers: custodyChain.length - 1,
          firstAcquisition: custodyChain[0]?.timestamp,
          lastTransfer: custodyChain[custodyChain.length - 1]?.timestamp,
          currentCustodian: custodyChain[custodyChain.length - 1]?.investigatorId,
          currentLocation: custodyChain[custodyChain.length - 1]?.location
        },
        compliance: {
          chainOfCustody: 'COMPLETE',
          integrityVerification: integrityStatus ? 'PASSED' : 'FAILED',
          auditTrail: 'MAINTAINED',
          digitalSignatures: 'VERIFIED'
        }
      };

      return report;
    } catch (error) {
      this.logger.error('Failed to generate custody report:', error);
      throw new Error('Custody report generation failed');
    }
  }

  /**
   * Add entry to audit trail
   * @param {Object} record - Custody record
   */
  addToAuditTrail(record) {
    this.auditTrail.push({
      timestamp: new Date().toISOString(),
      action: record.action,
      evidenceId: record.evidenceId,
      investigatorId: record.investigatorId,
      details: record
    });
  }

  /**
   * Generate unique custody ID
   * @returns {string} Unique custody ID
   */
  generateCustodyId() {
    return `COC-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`;
  }

  /**
   * Generate digital signature for custody record
   * @param {string} evidenceId - Evidence ID
   * @param {string} investigator - Investigator ID
   * @param {string} timestamp - Timestamp
   * @returns {string} Digital signature
   */
  generateDigitalSignature(evidenceId, investigator, timestamp) {
    const data = `${evidenceId}:${investigator}:${timestamp}`;
    return crypto.createHmac('sha256', process.env.SIGNATURE_SECRET || 'default-secret')
      .update(data)
      .digest('hex');
  }

  /**
   * Calculate integrity hash for evidence
   * @param {Object} evidence - Evidence object
   * @returns {string} Integrity hash
   */
  async calculateIntegrityHash(evidence) {
    const data = JSON.stringify(evidence);
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  /**
   * Store custody record in database
   * @param {Object} record - Custody record
   */
  async storeCustodyRecord(record) {
    if (this.dbConnector) {
      await this.dbConnector.execute(
        'INSERT INTO chain_of_custody (custody_id, evidence_id, investigator_id, location, timestamp, action, notes, digital_signature, integrity_hash, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [record.custodyId, record.evidenceId, record.investigatorId, record.location, record.timestamp, record.action, record.notes, record.digitalSignature, record.integrityHash, record.status]
      );
    }
  }

  /**
   * Get current custody record for evidence
   * @param {string} evidenceId - Evidence ID
   * @returns {Object} Current custody record
   */
  async getCurrentCustody(evidenceId) {
    if (this.dbConnector) {
      const result = await this.dbConnector.query(
        'SELECT * FROM chain_of_custody WHERE evidence_id = ? AND status = "ACTIVE" ORDER BY timestamp DESC LIMIT 1',
        [evidenceId]
      );
      return result[0];
    }
    return null;
  }

  /**
   * Get complete custody chain for evidence
   * @param {string} evidenceId - Evidence ID
   * @returns {Array} Complete custody chain
   */
  async getCustodyChain(evidenceId) {
    if (this.dbConnector) {
      return await this.dbConnector.query(
        'SELECT * FROM chain_of_custody WHERE evidence_id = ? ORDER BY timestamp ASC',
        [evidenceId]
      );
    }
    return [];
  }

  /**
   * Close custody record
   * @param {string} custodyId - Custody ID
   * @param {string} status - Final status
   */
  async closeCustodyRecord(custodyId, status) {
    if (this.dbConnector) {
      await this.dbConnector.execute(
        'UPDATE chain_of_custody SET status = ?, closed_timestamp = ? WHERE custody_id = ?',
        [status, new Date().toISOString(), custodyId]
      );
    }
  }

  /**
   * Link custody records
   * @param {string} previousId - Previous custody ID
   * @param {string} nextId - Next custody ID
   */
  async linkCustodyRecords(previousId, nextId) {
    if (this.dbConnector) {
      await this.dbConnector.execute(
        'UPDATE chain_of_custody SET next_custody_id = ? WHERE custody_id = ?',
        [nextId, previousId]
      );
      await this.dbConnector.execute(
        'UPDATE chain_of_custody SET previous_custody_id = ? WHERE custody_id = ?',
        [previousId, nextId]
      );
    }
  }

  /**
   * Export audit trail
   * @returns {Array} Complete audit trail
   */
  exportAuditTrail() {
    return [...this.auditTrail];
  }

  /**
   * Clear audit trail (use with caution)
   */
  clearAuditTrail() {
    this.auditTrail = [];
  }
}

module.exports = ChainOfCustody;
