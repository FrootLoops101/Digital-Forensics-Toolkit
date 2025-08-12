/**
 * Evidence Manager - Core Module
 * 
 * Handles evidence collection, tracking, and chain of custody management
 * Implements NIST SP 800-86 and ISO 27037 compliance standards
 */

const crypto = require('crypto');
const fs = require('fs-extra');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

class EvidenceManager {
  constructor(dbConnector, logger) {
    this.db = dbConnector;
    this.logger = logger;
    this.evidenceLog = [];
    this.custodyChain = new Map();
    this.config = require('../../config/tool-configuration.json');
    this.standards = require('../../config/forensic-standards.json');
  }

  /**
   * Add new evidence to the system
   * @param {Object} evidenceData - Evidence information
   * @returns {Object} Created evidence record
   */
  async addEvidence(evidenceData) {
    try {
      const {
        caseId,
        description,
        collector,
        location,
        sourceType,
        filePath,
        metadata = {}
      } = evidenceData;

      // Validate required fields
      if (!caseId || !description || !collector || !sourceType) {
        throw new Error('Missing required evidence fields');
      }

      // Generate unique evidence ID
      const evidenceId = uuidv4();
      const evidenceNumber = await this.generateEvidenceNumber(caseId);

      // Calculate initial hashes
      let hashes = {};
      if (filePath && await fs.pathExists(filePath)) {
        hashes = await this.calculateFileHashes(filePath);
      }

      // Create evidence record
      const evidence = {
        evidenceId,
        caseId,
        evidenceNumber,
        description,
        sourceType,
        filePath: filePath || null,
        collector,
        location,
        collectionDate: new Date().toISOString(),
        hashes,
        metadata,
        status: 'collected',
        integrityVerified: true,
        chainOfCustody: []
      };

      // Add to database
      await this.db.run(`
        INSERT INTO Evidence (
          evidence_id, case_id, evidence_number, description, source_type,
          file_path, collector_name, location, collection_date,
          hash_md5, hash_sha1, hash_sha256, metadata, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [
        evidenceId, caseId, evidenceNumber, description, sourceType,
        filePath, collector, location, evidence.collectionDate,
        hashes.md5 || null, hashes.sha1 || null, hashes.sha256 || null,
        JSON.stringify(metadata), evidence.status
      ]);

      // Initialize chain of custody
      await this.initializeChainOfCustody(evidenceId, collector, 'Initial collection');

      // Log evidence addition
      this.logger.info(`Evidence added: ${evidenceNumber}`, {
        evidenceId,
        caseId,
        collector,
        sourceType
      });

      return evidence;

    } catch (error) {
      this.logger.error('Failed to add evidence:', error);
      throw error;
    }
  }

  /**
   * Transfer custody of evidence between individuals
   * @param {string} evidenceId - Evidence identifier
   * @param {string} fromPerson - Current custodian
   * @param {string} toPerson - New custodian
   * @param {string} reason - Reason for transfer
   * @returns {Object} Transfer record
   */
  async transferCustody(evidenceId, fromPerson, toPerson, reason) {
    try {
      // Verify current custody
      const currentCustody = await this.getCurrentCustody(evidenceId);
      if (currentCustody.custodian !== fromPerson) {
        throw new Error('Current custodian mismatch');
      }

      // Create transfer record
      const transferId = uuidv4();
      const transfer = {
        transferId,
        evidenceId,
        fromPerson,
        toPerson,
        reason,
        transferDate: new Date().toISOString(),
        digitalSignature: await this.createDigitalSignature(evidenceId, fromPerson, toPerson)
      };

      // Add to database
      await this.db.run(`
        INSERT INTO CustodyChain (
          custody_id, evidence_id, from_person, to_person,
          transfer_date, transfer_reason, digital_signature
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `, [
        transferId, evidenceId, fromPerson, toPerson,
        transfer.transferDate, reason, transfer.digitalSignature
      ]);

      // Update evidence status
      await this.db.run(`
        UPDATE Evidence SET status = 'transferred' WHERE evidence_id = ?
      `, [evidenceId]);

      // Log transfer
      this.logger.info(`Custody transferred: ${evidenceId}`, {
        fromPerson,
        toPerson,
        reason,
        transferId
      });

      return transfer;

    } catch (error) {
      this.logger.error('Failed to transfer custody:', error);
      throw error;
    }
  }

  /**
   * Verify evidence integrity
   * @param {string} evidenceId - Evidence identifier
   * @returns {Object} Integrity verification results
   */
  async verifyEvidenceIntegrity(evidenceId) {
    try {
      const evidence = await this.getEvidence(evidenceId);
      if (!evidence) {
        throw new Error('Evidence not found');
      }

      if (!evidence.filePath || !await fs.pathExists(evidence.filePath)) {
        return {
          evidenceId,
          integrityVerified: false,
          reason: 'File not accessible',
          timestamp: new Date().toISOString()
        };
      }

      // Calculate current hashes
      const currentHashes = await this.calculateFileHashes(evidence.filePath);
      const originalHashes = {
        md5: evidence.hashMd5,
        sha1: evidence.hashSha1,
        sha256: evidence.hashSha256
      };

      // Compare hashes
      const integrityVerified = Object.keys(currentHashes).every(algorithm => 
        currentHashes[algorithm] === originalHashes[algorithm]
      );

      const result = {
        evidenceId,
        integrityVerified,
        originalHashes,
        currentHashes,
        timestamp: new Date().toISOString()
      };

      // Update integrity status
      await this.db.run(`
        UPDATE Evidence SET integrity_verified = ? WHERE evidence_id = ?
      `, [integrityVerified, evidenceId]);

      // Log verification
      this.logger.info(`Integrity verification completed: ${evidenceId}`, {
        integrityVerified,
        timestamp: result.timestamp
      });

      return result;

    } catch (error) {
      this.logger.error('Failed to verify evidence integrity:', error);
      throw error;
    }
  }

  /**
   * Generate chain of custody report
   * @param {string} evidenceId - Evidence identifier
   * @returns {Object} Custody report
   */
  async generateCustodyReport(evidenceId) {
    try {
      const evidence = await this.getEvidence(evidenceId);
      const custodyChain = await this.getCustodyChain(evidenceId);

      const report = {
        evidenceId,
        evidenceNumber: evidence.evidenceNumber,
        description: evidence.description,
        caseId: evidence.caseId,
        collectionDate: evidence.collectionDate,
        currentStatus: evidence.status,
        integrityVerified: evidence.integrityVerified,
        custodyChain: custodyChain.map(entry => ({
          transferDate: entry.transferDate,
          fromPerson: entry.fromPerson,
          toPerson: entry.toPerson,
          reason: entry.transferReason,
          digitalSignature: entry.digitalSignature
        })),
        reportGenerated: new Date().toISOString(),
        compliance: {
          nist: this.standards.nist.sp80086.compliance.chainOfCustody.required,
          iso: this.standards.iso['27037'].compliance.preservation.required
        }
      };

      this.logger.info(`Custody report generated: ${evidenceId}`);
      return report;

    } catch (error) {
      this.logger.error('Failed to generate custody report:', error);
      throw error;
    }
  }

  /**
   * Get evidence by ID
   * @param {string} evidenceId - Evidence identifier
   * @returns {Object} Evidence record
   */
  async getEvidence(evidenceId) {
    try {
      const evidence = await this.db.get(`
        SELECT * FROM Evidence WHERE evidence_id = ?
      `, [evidenceId]);

      return evidence;
    } catch (error) {
      this.logger.error('Failed to get evidence:', error);
      throw error;
    }
  }

  /**
   * Get current custody information
   * @param {string} evidenceId - Evidence identifier
   * @returns {Object} Current custody record
   */
  async getCurrentCustody(evidenceId) {
    try {
      const custody = await this.db.get(`
        SELECT * FROM CustodyChain 
        WHERE evidence_id = ? 
        ORDER BY transfer_date DESC 
        LIMIT 1
      `, [evidenceId]);

      return custody;
    } catch (error) {
      this.logger.error('Failed to get current custody:', error);
      throw error;
    }
  }

  /**
   * Get complete custody chain
   * @param {string} evidenceId - Evidence identifier
   * @returns {Array} Custody chain records
   */
  async getCustodyChain(evidenceId) {
    try {
      const chain = await this.db.all(`
        SELECT * FROM CustodyChain 
        WHERE evidence_id = ? 
        ORDER BY transfer_date ASC
      `, [evidenceId]);

      return chain;
    } catch (error) {
      this.logger.error('Failed to get custody chain:', error);
      throw error;
    }
  }

  /**
   * Calculate file hashes using multiple algorithms
   * @param {string} filePath - Path to file
   * @returns {Object} Hash values
   */
  async calculateFileHashes(filePath) {
    try {
      const algorithms = this.config.forensics.hashAlgorithms;
      const hashes = {};

      for (const algorithm of algorithms) {
        const hash = crypto.createHash(algorithm);
        const fileBuffer = await fs.readFile(filePath);
        hash.update(fileBuffer);
        hashes[algorithm] = hash.digest('hex');
      }

      return hashes;
    } catch (error) {
      this.logger.error('Failed to calculate file hashes:', error);
      throw error;
    }
  }

  /**
   * Generate evidence number for case
   * @param {string} caseId - Case identifier
   * @returns {string} Evidence number
   */
  async generateEvidenceNumber(caseId) {
    try {
      const count = await this.db.get(`
        SELECT COUNT(*) as count FROM Evidence WHERE case_id = ?
      `, [caseId]);

      const caseInfo = await this.db.get(`
        SELECT case_number FROM Cases WHERE case_id = ?
      `, [caseId]);

      return `${caseInfo.caseNumber}-E${String(count.count + 1).padStart(3, '0')}`;
    } catch (error) {
      this.logger.error('Failed to generate evidence number:', error);
      throw error;
    }
  }

  /**
   * Initialize chain of custody for new evidence
   * @param {string} evidenceId - Evidence identifier
   * @param {string} collector - Initial collector
   * @param {string} reason - Collection reason
   */
  async initializeChainOfCustody(evidenceId, collector, reason) {
    try {
      const transferId = uuidv4();
      await this.db.run(`
        INSERT INTO CustodyChain (
          custody_id, evidence_id, from_person, to_person,
          transfer_date, transfer_reason, digital_signature
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `, [
        transferId, evidenceId, 'System', collector,
        new Date().toISOString(), reason, 'Initial collection signature'
      ]);
    } catch (error) {
      this.logger.error('Failed to initialize chain of custody:', error);
      throw error;
    }
  }

  /**
   * Create digital signature for custody transfer
   * @param {string} evidenceId - Evidence identifier
   * @param {string} fromPerson - Current custodian
   * @param {string} toPerson - New custodian
   * @returns {string} Digital signature
   */
  async createDigitalSignature(evidenceId, fromPerson, toPerson) {
    try {
      const data = `${evidenceId}:${fromPerson}:${toPerson}:${Date.now()}`;
      const signature = crypto.createHmac('sha256', this.config.security.jwtSecret)
        .update(data)
        .digest('hex');
      
      return signature;
    } catch (error) {
      this.logger.error('Failed to create digital signature:', error);
      throw error;
    }
  }

  /**
   * Search evidence by various criteria
   * @param {Object} criteria - Search criteria
   * @returns {Array} Matching evidence records
   */
  async searchEvidence(criteria) {
    try {
      let query = 'SELECT * FROM Evidence WHERE 1=1';
      const params = [];

      if (criteria.caseId) {
        query += ' AND case_id = ?';
        params.push(criteria.caseId);
      }

      if (criteria.collector) {
        query += ' AND collector_name LIKE ?';
        params.push(`%${criteria.collector}%`);
      }

      if (criteria.status) {
        query += ' AND status = ?';
        params.push(criteria.status);
      }

      if (criteria.dateFrom) {
        query += ' AND collection_date >= ?';
        params.push(criteria.dateFrom);
      }

      if (criteria.dateTo) {
        query += ' AND collection_date <= ?';
        params.push(criteria.dateTo);
      }

      query += ' ORDER BY collection_date DESC';

      const evidence = await this.db.all(query, params);
      return evidence;
    } catch (error) {
      this.logger.error('Failed to search evidence:', error);
      throw error;
    }
  }
}

module.exports = EvidenceManager;
