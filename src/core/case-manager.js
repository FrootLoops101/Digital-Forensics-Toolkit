/**
 * Case Manager - Core Module
 * 
 * Handles case file organization, investigation workflow, and case metadata
 * Implements case lifecycle management and investigator assignment
 */

const { v4: uuidv4 } = require('uuid');
const fs = require('fs-extra');
const path = require('path');

class CaseManager {
  constructor(dbConnector, logger) {
    this.db = dbConnector;
    this.logger = logger;
    this.config = require('../../config/tool-configuration.json');
    this.standards = require('../../config/forensic-standards.json');
  }

  /**
   * Create a new investigation case
   * @param {Object} caseData - Case information
   * @returns {Object} Created case record
   */
  async createCase(caseData) {
    try {
      const {
        caseNumber,
        caseTitle,
        caseDescription,
        investigatorId,
        caseType,
        priority = 'medium',
        client = null,
        tags = []
      } =caseData;

      // Validate required fields
      if (!caseNumber || !caseTitle || !investigatorId) {
        throw new Error('Missing required case fields');
      }

      // Check if case number already exists
      const existingCase = await this.db.get(`
        SELECT case_id FROM Cases WHERE case_number = ?
      `, [caseNumber]);

      if (existingCase) {
        throw new Error('Case number already exists');
      }

      // Generate unique case ID
      const caseId = uuidv4();

      // Create case record
      const caseRecord = {
        caseId,
        caseNumber,
        caseTitle,
        caseDescription,
        investigatorId,
        caseType,
        priority,
        client,
        tags: JSON.stringify(tags),
        status: 'active',
        createdDate: new Date().toISOString(),
        lastModified: new Date().toISOString(),
        metadata: {}
      };

      // Add to database
      await this.db.run(`
        INSERT INTO Cases (
          case_id, case_number, case_title, case_description,
          investigator_id, case_type, priority, client, tags,
          status, created_date, last_modified, metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [
        caseId, caseNumber, caseTitle, caseDescription,
        investigatorId, caseType, priority, client, caseRecord.tags,
        caseRecord.status, caseRecord.createdDate, caseRecord.lastModified,
        JSON.stringify(caseRecord.metadata)
      ]);

      // Create case directory structure
      await this.createCaseDirectory(caseId, caseNumber);

      // Log case creation
      this.logger.info(`Case created: ${caseNumber}`, {
        caseId,
        investigatorId,
        caseType,
        priority
      });

      return caseRecord;

    } catch (error) {
      this.logger.error('Failed to create case:', error);
      throw error;
    }
  }

  /**
   * Update case information
   * @param {string} caseId - Case identifier
   * @param {Object} updates - Case updates
   * @returns {Object} Updated case record
   */
  async updateCase(caseId, updates) {
    try {
      const allowedUpdates = [
        'caseTitle', 'caseDescription', 'investigatorId', 'caseType',
        'priority', 'client', 'tags', 'status', 'metadata'
      ];

      const updateFields = [];
      const updateValues = [];

      for (const [key, value] of Object.entries(updates)) {
        if (allowedUpdates.includes(key)) {
          updateFields.push(`${key} = ?`);
          updateValues.push(typeof value === 'object' ? JSON.stringify(value) : value);
        }
      }

      if (updateFields.length === 0) {
        throw new Error('No valid update fields provided');
      }

      // Add last modified timestamp
      updateFields.push('last_modified = ?');
      updateValues.push(new Date().toISOString());

      const query = `UPDATE Cases SET ${updateFields.join(', ')} WHERE case_id = ?`;
      updateValues.push(caseId);

      await this.db.run(query, updateValues);

      // Get updated case
      const updatedCase = await this.getCase(caseId);

      this.logger.info(`Case updated: ${caseId}`, {
        updatedFields: Object.keys(updates),
        timestamp: new Date().toISOString()
      });

      return updatedCase;

    } catch (error) {
      this.logger.error('Failed to update case:', error);
      throw error;
    }
  }

  /**
   * Get case by ID
   * @param {string} caseId - Case identifier
   * @returns {Object} Case record
   */
  async getCase(caseId) {
    try {
      const caseRecord = await this.db.get(`
        SELECT * FROM Cases WHERE case_id = ?
      `, [caseId]);

      if (!caseRecord) {
        return null;
      }

      // Parse JSON fields
      if (caseRecord.tags) {
        caseRecord.tags = JSON.parse(caseRecord.tags);
      }
      if (caseRecord.metadata) {
        caseRecord.metadata = JSON.parse(caseRecord.metadata);
      }

      return caseRecord;
    } catch (error) {
      this.logger.error('Failed to get case:', error);
      throw error;
    }
  }

  /**
   * Get case by case number
   * @param {string} caseNumber - Case number
   * @returns {Object} Case record
   */
  async getCaseByNumber(caseNumber) {
    try {
      const caseRecord = await this.db.get(`
        SELECT * FROM Cases WHERE case_number = ?
      `, [caseNumber]);

      if (!caseRecord) {
        return null;
      }

      // Parse JSON fields
      if (caseRecord.tags) {
        caseRecord.tags = JSON.parse(caseRecord.tags);
      }
      if (caseRecord.metadata) {
        caseRecord.metadata = JSON.parse(caseRecord.metadata);
      }

      return caseRecord;
    } catch (error) {
      this.logger.error('Failed to get case by number:', error);
      throw error;
    }
  }

  /**
   * List all cases with optional filtering
   * @param {Object} filters - Filter criteria
   * @returns {Array} Case records
   */
  async listCases(filters = {}) {
    try {
      let query = 'SELECT * FROM Cases WHERE 1=1';
      const params = [];

      if (filters.status) {
        query += ' AND status = ?';
        params.push(filters.status);
      }

      if (filters.investigatorId) {
        query += ' AND investigator_id = ?';
        params.push(filters.investigatorId);
      }

      if (filters.caseType) {
        query += ' AND case_type = ?';
        params.push(filters.caseType);
      }

      if (filters.priority) {
        query += ' AND priority = ?';
        params.push(filters.priority);
      }

      if (filters.dateFrom) {
        query += ' AND created_date >= ?';
        params.push(filters.dateFrom);
      }

      if (filters.dateTo) {
        query += ' AND created_date <= ?';
        params.push(filters.dateTo);
      }

      query += ' ORDER BY created_date DESC';

      const cases = await this.db.all(query, params);

      // Parse JSON fields for each case
      cases.forEach(caseRecord => {
        if (caseRecord.tags) {
          caseRecord.tags = JSON.parse(caseRecord.tags);
        }
        if (caseRecord.metadata) {
          caseRecord.metadata = JSON.parse(caseRecord.metadata);
        }
      });

      return cases;
    } catch (error) {
      this.logger.error('Failed to list cases:', error);
      throw error;
    }
  }

  /**
   * Close a case
   * @param {string} caseId - Case identifier
   * @param {string} closureReason - Reason for closure
   * @param {string} closedBy - Investigator who closed the case
   * @returns {Object} Updated case record
   */
  async closeCase(caseId, closureReason, closedBy) {
    try {
      const caseRecord = await this.getCase(caseId);
      if (!caseRecord) {
        throw new Error('Case not found');
      }

      if (caseRecord.status === 'closed') {
        throw new Error('Case is already closed');
      }

      // Update case status
      await this.db.run(`
        UPDATE Cases SET 
          status = 'closed',
          last_modified = ?,
          metadata = ?
        WHERE case_id = ?
      `, [
        new Date().toISOString(),
        JSON.stringify({
          ...caseRecord.metadata,
          closureReason,
          closedBy,
          closedDate: new Date().toISOString()
        }),
        caseId
      ]);

      this.logger.info(`Case closed: ${caseId}`, {
        closedBy,
        closureReason,
        timestamp: new Date().toISOString()
      });

      return await this.getCase(caseId);

    } catch (error) {
      this.logger.error('Failed to close case:', error);
      throw error;
    }
  }

  /**
   * Reopen a closed case
   * @param {string} caseId - Case identifier
   * @param {string} reopenReason - Reason for reopening
   * @param {string} reopenedBy - Investigator who reopened the case
   * @returns {Object} Updated case record
   */
  async reopenCase(caseId, reopenReason, reopenedBy) {
    try {
      const caseRecord = await this.getCase(caseId);
      if (!caseRecord) {
        throw new Error('Case not found');
      }

      if (caseRecord.status !== 'closed') {
        throw new Error('Case is not closed');
      }

      // Update case status
      await this.db.run(`
        UPDATE Cases SET 
          status = 'active',
          last_modified = ?,
          metadata = ?
        WHERE case_id = ?
      `, [
        new Date().toISOString(),
        JSON.stringify({
          ...caseRecord.metadata,
          reopenReason,
          reopenedBy,
          reopenedDate: new Date().toISOString()
        }),
        caseId
      ]);

      this.logger.info(`Case reopened: ${caseId}`, {
        reopenedBy,
        reopenReason,
        timestamp: new Date().toISOString()
      });

      return await this.getCase(caseId);

    } catch (error) {
      this.logger.error('Failed to reopen case:', error);
      throw error;
    }
  }

  /**
   * Get case statistics
   * @param {string} investigatorId - Optional investigator filter
   * @returns {Object} Case statistics
   */
  async getCaseStatistics(investigatorId = null) {
    try {
      let whereClause = '';
      const params = [];

      if (investigatorId) {
        whereClause = 'WHERE investigator_id = ?';
        params.push(investigatorId);
      }

      const stats = await this.db.get(`
        SELECT 
          COUNT(*) as totalCases,
          SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as activeCases,
          SUM(CASE WHEN status = 'closed' THEN 1 ELSE 0 END) as closedCases,
          SUM(CASE WHEN priority = 'high' THEN 1 ELSE 0 END) as highPriorityCases,
          SUM(CASE WHEN priority = 'medium' THEN 1 ELSE 0 END) as mediumPriorityCases,
          SUM(CASE WHEN priority = 'low' THEN 1 ELSE 0 END) as lowPriorityCases
        FROM Cases ${whereClause}
      `, params);

      return stats;
    } catch (error) {
      this.logger.error('Failed to get case statistics:', error);
      throw error;
    }
  }

  /**
   * Create case directory structure
   * @param {string} caseId - Case identifier
   * @param {string} caseNumber - Case number
   */
  async createCaseDirectory(caseId, caseNumber) {
    try {
      const basePath = path.join(this.config.forensics.evidenceStorage, caseNumber);
      
      // Create main case directory
      await fs.ensureDir(basePath);

      // Create subdirectories
      const subdirs = [
        'evidence',
        'acquisition',
        'analysis',
        'reports',
        'working',
        'backups'
      ];

      for (const subdir of subdirs) {
        await fs.ensureDir(path.join(basePath, subdir));
      }

      // Create case info file
      const caseInfo = {
        caseId,
        caseNumber,
        createdDate: new Date().toISOString(),
        directoryStructure: subdirs,
        notes: 'Case directory created automatically'
      };

      await fs.writeJson(path.join(basePath, 'case-info.json'), caseInfo, { spaces: 2 });

      this.logger.info(`Case directory structure created: ${basePath}`);

    } catch (error) {
      this.logger.error('Failed to create case directory:', error);
      throw error;
    }
  }

  /**
   * Search cases by various criteria
   * @param {Object} searchCriteria - Search parameters
   * @returns {Array} Matching case records
   */
  async searchCases(searchCriteria) {
    try {
      let query = 'SELECT * FROM Cases WHERE 1=1';
      const params = [];

      if (searchCriteria.keyword) {
        query += ` AND (
          case_title LIKE ? OR 
          case_description LIKE ? OR 
          case_number LIKE ?
        )`;
        const keyword = `%${searchCriteria.keyword}%`;
        params.push(keyword, keyword, keyword);
      }

      if (searchCriteria.tags && searchCriteria.tags.length > 0) {
        const tagConditions = searchCriteria.tags.map(() => 'tags LIKE ?');
        query += ` AND (${tagConditions.join(' OR ')})`;
        searchCriteria.tags.forEach(tag => {
          params.push(`%${tag}%`);
        });
      }

      if (searchCriteria.status) {
        query += ' AND status = ?';
        params.push(searchCriteria.status);
      }

      if (searchCriteria.caseType) {
        query += ' AND case_type = ?';
        params.push(searchCriteria.caseType);
      }

      query += ' ORDER BY created_date DESC';

      const cases = await this.db.all(query, params);

      // Parse JSON fields
      cases.forEach(caseRecord => {
        if (caseRecord.tags) {
          caseRecord.tags = JSON.parse(caseRecord.tags);
        }
        if (caseRecord.metadata) {
          caseRecord.metadata = JSON.parse(caseRecord.metadata);
        }
      });

      return cases;
    } catch (error) {
      this.logger.error('Failed to search cases:', error);
      throw error;
    }
  }

  /**
   * Archive a case
   * @param {string} caseId - Case identifier
   * @param {string} archiveReason - Reason for archiving
   * @param {string} archivedBy - Investigator who archived the case
   * @returns {Object} Updated case record
   */
  async archiveCase(caseId, archiveReason, archivedBy) {
    try {
      const caseRecord = await this.getCase(caseId);
      if (!caseRecord) {
        throw new Error('Case not found');
      }

      if (caseRecord.status === 'archived') {
        throw new Error('Case is already archived');
      }

      // Update case status
      await this.db.run(`
        UPDATE Cases SET 
          status = 'archived',
          last_modified = ?,
          metadata = ?
        WHERE case_id = ?
      `, [
        new Date().toISOString(),
        JSON.stringify({
          ...caseRecord.metadata,
          archiveReason,
          archivedBy,
          archivedDate: new Date().toISOString()
        }),
        caseId
      ]);

      this.logger.info(`Case archived: ${caseId}`, {
        archivedBy,
        archiveReason,
        timestamp: new Date().toISOString()
      });

      return await this.getCase(caseId);

    } catch (error) {
      this.logger.error('Failed to archive case:', error);
      throw error;
    }
  }
}

module.exports = CaseManager;
