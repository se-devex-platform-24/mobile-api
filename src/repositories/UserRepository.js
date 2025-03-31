const User = require('../models/User');
const crypto = require('crypto');
const { dbConfig } = require('../config/database');

class UserRepository {
  constructor() {
    this.model = User;
    this.encryptionKey = process.env.DB_ENCRYPTION_KEY;
    
    if (!this.encryptionKey) {
      throw new Error('Database encryption key not found in environment variables');
    }
  }

  // Encrypt sensitive data before storing
  encryptData(data) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(this.encryptionKey, 'hex'), iv);
    
    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return {
      encryptedData: encrypted,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex')
    };
  }

  // Decrypt sensitive data after retrieval
  decryptData(encryptedData, iv, authTag) {
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      Buffer.from(this.encryptionKey, 'hex'),
      Buffer.from(iv, 'hex')
    );
    
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return JSON.parse(decrypted);
  }

  // Create a new user with encrypted sensitive data
  async createUser(userData) {
    try {
      // Encrypt sensitive information
      const sensitiveData = {
        firstName: userData.firstName,
        lastName: userData.lastName,
        email: userData.email
      };
      
      const encryptedData = this.encryptData(sensitiveData);
      
      // Create user with encrypted data
      const user = new this.model({
        ...userData,
        firstName: undefined,
        lastName: undefined,
        email: undefined,
        encryptedData: encryptedData.encryptedData,
        iv: encryptedData.iv,
        authTag: encryptedData.authTag
      });

      const savedUser = await user.save();
      return this.sanitizeUser(savedUser);
    } catch (error) {
      throw new Error(`Error creating user: ${error.message}`);
    }
  }

  // Find user by ID with decrypted data
  async findById(userId) {
    try {
      const user = await this.model.findById(userId).select('+encryptedData +iv +authTag');
      if (!user) return null;

      return this.decryptUserData(user);
    } catch (error) {
      throw new Error(`Error finding user: ${error.message}`);
    }
  }

  // Find user by email with decrypted data
  async findByEmail(email) {
    try {
      // Note: This requires a database index on the email field within encryptedData
      const users = await this.model.find().select('+encryptedData +iv +authTag');
      
      // Decrypt and filter users to find matching email
      for (const user of users) {
        const decryptedUser = this.decryptUserData(user);
        if (decryptedUser.email === email) {
          return decryptedUser;
        }
      }
      
      return null;
    } catch (error) {
      throw new Error(`Error finding user by email: ${error.message}`);
    }
  }

  // Update user data with encryption
  async updateUser(userId, updateData) {
    try {
      const user = await this.model.findById(userId).select('+encryptedData +iv +authTag');
      if (!user) throw new Error('User not found');

      const currentDecryptedData = this.decryptData(
        user.encryptedData,
        user.iv,
        user.authTag
      );

      const newSensitiveData = {
        ...currentDecryptedData,
        ...updateData
      };

      const encryptedData = this.encryptData(newSensitiveData);

      const updatedUser = await this.model.findByIdAndUpdate(
        userId,
        {
          ...updateData,
          firstName: undefined,
          lastName: undefined,
          email: undefined,
          encryptedData: encryptedData.encryptedData,
          iv: encryptedData.iv,
          authTag: encryptedData.authTag
        },
        { new: true }
      );

      return this.sanitizeUser(updatedUser);
    } catch (error) {
      throw new Error(`Error updating user: ${error.message}`);
    }
  }

  // Delete user securely
  async deleteUser(userId) {
    try {
      const user = await this.model.findByIdAndDelete(userId);
      return !!user;
    } catch (error) {
      throw new Error(`Error deleting user: ${error.message}`);
    }
  }

  // Decrypt user data and return sanitized user object
  decryptUserData(user) {
    if (!user.encryptedData || !user.iv || !user.authTag) {
      return user;
    }

    const decryptedData = this.decryptData(
      user.encryptedData,
      user.iv,
      user.authTag
    );

    const userObject = user.toObject();
    delete userObject.encryptedData;
    delete userObject.iv;
    delete userObject.authTag;

    return {
      ...userObject,
      ...decryptedData
    };
  }

  // Remove sensitive data before sending to client
  sanitizeUser(user) {
    const userObject = user.toObject();
    delete userObject.password;
    delete userObject.resetPasswordToken;
    delete userObject.resetPasswordExpire;
    delete userObject.encryptedData;
    delete userObject.iv;
    delete userObject.authTag;
    return userObject;
  }
}

module.exports = new UserRepository();