/**
 * Enhanced Hash Calculator for Digital Forensics
 * 
 * This module provides comprehensive hashing capabilities for digital evidence,
 * supporting multiple hash algorithms and forensic integrity verification.
 * 
 * Features:
 * - Multiple hash algorithms (MD5, SHA-1, SHA-256, SHA-512)
 * - File integrity verification
 * - Hash collision detection
 * - Forensic standard compliance
 * - Batch processing capabilities
 */

const crypto = require('crypto');
const fs = require('fs-extra');
const path = require('path');

class HashCalculator {
  constructor(logger) {
    this.logger = logger;
    this.supportedAlgorithms = ['md5', 'sha1', 'sha256', 'sha512', 'sha3-256'];
    this.hashCache = new Map();
  }

  /**
   * Calculate multiple hashes for a file
   * @param {string} filePath - Path to the file
   * @param {Array} algorithms - Array of hash algorithms to use
   * @returns {Object} Object containing all calculated hashes
   */
  async calculateFileHashes(filePath, algorithms = ['md5', 'sha256']) {
    try {
      if (!await fs.pathExists(filePath)) {
        throw new Error(`File not found: ${filePath}`);
      }

      const fileStats = await fs.stat(filePath);
      const fileSize = fileStats.size;
      
      this.logger.info(`Calculating hashes for file: ${filePath}`, { fileSize });

      const hashes = {};
      const fileStream = fs.createReadStream(filePath);
      
      // Initialize hash objects for each algorithm
      const hashObjects = {};
      algorithms.forEach(alg => {
        if (this.supportedAlgorithms.includes(alg)) {
          hashObjects[alg] = crypto.createHash(alg);
        }
      });

      // Process file in chunks
      return new Promise((resolve, reject) => {
        fileStream.on('data', (chunk) => {
          Object.values(hashObjects).forEach(hashObj => {
            hashObj.update(chunk);
          });
        });

        fileStream.on('end', () => {
          algorithms.forEach(alg => {
            if (hashObjects[alg]) {
              hashes[alg] = hashObjects[alg].digest('hex');
            }
          });

          const result = {
            filePath,
            fileSize,
            timestamp: new Date().toISOString(),
            hashes,
            algorithms
          };

          // Cache the result
          this.hashCache.set(filePath, result);
          
          this.logger.info(`Hash calculation completed for ${filePath}`, { algorithms });
          resolve(result);
        });

        fileStream.on('error', (error) => {
          this.logger.error(`Error reading file ${filePath}:`, error);
          reject(error);
        });
      });

    } catch (error) {
      this.logger.error(`Failed to calculate hashes for ${filePath}:`, error);
      throw error;
    }
  }

  /**
   * Calculate hash for a string or buffer
   * @param {string|Buffer} data - Data to hash
   * @param {string} algorithm - Hash algorithm to use
   * @returns {string} Calculated hash
   */
  calculateDataHash(data, algorithm = 'sha256') {
    try {
      if (!this.supportedAlgorithms.includes(algorithm)) {
        throw new Error(`Unsupported hash algorithm: ${algorithm}`);
      }

      const hash = crypto.createHash(algorithm);
      hash.update(data);
      return hash.digest('hex');
    } catch (error) {
      this.logger.error(`Failed to calculate hash for data:`, error);
      throw error;
    }
  }

  /**
   * Verify file integrity by comparing hashes
   * @param {string} filePath - Path to the file
   * @param {Object} expectedHashes - Object containing expected hashes
   * @returns {Object} Verification result
   */
  async verifyFileIntegrity(filePath, expectedHashes) {
    try {
      const currentHashes = await this.calculateFileHashes(filePath, Object.keys(expectedHashes));
      
      const verification = {
        filePath,
        timestamp: new Date().toISOString(),
        integrity: true,
        mismatches: [],
        details: {}
      };

      // Compare each hash
      Object.keys(expectedHashes).forEach(algorithm => {
        const expected = expectedHashes[algorithm];
        const current = currentHashes.hashes[algorithm];
        
        if (expected !== current) {
          verification.integrity = false;
          verification.mismatches.push(algorithm);
          verification.details[algorithm] = {
            expected,
            current,
            match: false
          };
        } else {
          verification.details[algorithm] = {
            expected,
            current,
            match: true
          };
        }
      });

      this.logger.info(`File integrity verification completed for ${filePath}`, {
        integrity: verification.integrity,
        mismatches: verification.mismatches.length
      });

      return verification;
    } catch (error) {
      this.logger.error(`Failed to verify file integrity for ${filePath}:`, error);
      throw error;
    }
  }

  /**
   * Calculate hash for a directory (recursive)
   * @param {string} dirPath - Path to the directory
   * @param {Array} algorithms - Array of hash algorithms to use
   * @returns {Object} Directory hash information
   */
  async calculateDirectoryHashes(dirPath, algorithms = ['sha256']) {
    try {
      if (!await fs.pathExists(dirPath)) {
        throw new Error(`Directory not found: ${dirPath}`);
      }

      const files = await this.getAllFiles(dirPath);
      const results = {
        directory: dirPath,
        timestamp: new Date().toISOString(),
        totalFiles: files.length,
        fileHashes: {},
        directoryHash: null
      };

      // Calculate hashes for all files
      for (const file of files) {
        try {
          const fileHashes = await this.calculateFileHashes(file, algorithms);
          results.fileHashes[file] = fileHashes;
        } catch (error) {
          this.logger.warn(`Failed to hash file ${file}:`, error);
        }
      }

      // Calculate directory hash based on file hashes
      const directoryData = JSON.stringify(results.fileHashes);
      results.directoryHash = this.calculateDataHash(directoryData, algorithms[0]);

      this.logger.info(`Directory hash calculation completed for ${dirPath}`, {
        totalFiles: results.totalFiles
      });

      return results;
    } catch (error) {
      this.logger.error(`Failed to calculate directory hashes for ${dirPath}:`, error);
      throw error;
    }
  }

  /**
   * Get all files in a directory recursively
   * @param {string} dirPath - Directory path
   * @returns {Array} Array of file paths
   */
  async getAllFiles(dirPath) {
    const files = [];
    
    const items = await fs.readdir(dirPath);
    
    for (const item of items) {
      const fullPath = path.join(dirPath, item);
      const stat = await fs.stat(fullPath);
      
      if (stat.isDirectory()) {
        const subFiles = await this.getAllFiles(fullPath);
        files.push(...subFiles);
      } else {
        files.push(fullPath);
      }
    }
    
    return files;
  }

  /**
   * Detect potential hash collisions
   * @param {Array} filePaths - Array of file paths to check
   * @param {string} algorithm - Hash algorithm to use
   * @returns {Object} Collision detection results
   */
  async detectHashCollisions(filePaths, algorithm = 'sha256') {
    try {
      const hashMap = new Map();
      const collisions = [];
      
      for (const filePath of filePaths) {
        const hash = await this.calculateFileHashes(filePath, [algorithm]);
        const hashValue = hash.hashes[algorithm];
        
        if (hashMap.has(hashValue)) {
          collisions.push({
            hash: hashValue,
            files: [hashMap.get(hashValue), filePath]
          });
        } else {
          hashMap.set(hashValue, filePath);
        }
      }

      const result = {
        algorithm,
        totalFiles: filePaths.length,
        uniqueHashes: hashMap.size,
        collisions: collisions.length,
        collisionDetails: collisions
      };

      this.logger.info(`Hash collision detection completed`, result);
      return result;
    } catch (error) {
      this.logger.error('Failed to detect hash collisions:', error);
      throw error;
    }
  }

  /**
   * Generate hash report for forensic documentation
   * @param {string} target - File or directory path
   * @param {Array} algorithms - Hash algorithms to use
   * @returns {Object} Comprehensive hash report
   */
  async generateHashReport(target, algorithms = ['md5', 'sha1', 'sha256']) {
    try {
      const stat = await fs.stat(target);
      let hashData;
      
      if (stat.isDirectory()) {
        hashData = await this.calculateDirectoryHashes(target, algorithms);
      } else {
        hashData = await this.calculateFileHashes(target, algorithms);
      }

      const report = {
        target,
        type: stat.isDirectory() ? 'directory' : 'file',
        timestamp: new Date().toISOString(),
        algorithms,
        hashData,
        metadata: {
          size: stat.size,
          created: stat.birthtime,
          modified: stat.mtime,
          permissions: stat.mode
        },
        forensic: {
          integrity: true,
          timestamp: new Date().toISOString(),
          investigator: process.env.INVESTIGATOR_ID || 'unknown',
          caseId: process.env.CASE_ID || 'unknown'
        }
      };

      this.logger.info(`Hash report generated for ${target}`);
      return report;
    } catch (error) {
      this.logger.error(`Failed to generate hash report for ${target}:`, error);
      throw error;
    }
  }

  /**
   * Clear hash cache
   */
  clearCache() {
    this.hashCache.clear();
    this.logger.info('Hash cache cleared');
  }

  /**
   * Get cache statistics
   * @returns {Object} Cache statistics
   */
  getCacheStats() {
    return {
      size: this.hashCache.size,
      algorithms: this.supportedAlgorithms
    };
  }
}

module.exports = HashCalculator;
