const axios = require('axios');
const crypto = require('crypto');

const SUMSUB_APP_TOKEN = process.env.SUMSUB_APP_TOKEN;
const SUMSUB_SECRET_KEY = process.env.SUMSUB_SECRET_KEY;
const SUMSUB_BASE_URL = process.env.SUMSUB_BASE_URL;
const LEVEL_NAME = process.env.LEVEL_NAME;

function generateSignature(ts, method, path, body) {
  const hmac = crypto.createHmac('sha256', SUMSUB_SECRET_KEY);
  const data = ts + method.toUpperCase() + path;
  
  // Critical fix: Handle body differently based on its type
  if (body === null || body === undefined) {
    hmac.update(data);
  } else {
    hmac.update(data + JSON.stringify(body));
  }
  
  return hmac.digest('hex');
}

const generateVerificationToken = async (userId) => {
  try {
    // Generate a secure random token
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000); 
    
    return {
      token,
      expiresAt
    };
  } catch (error) {
    console.error('Verification Token Generation Error:', error);
    throw error;
  }
};


const createApplicant = async (externalUserId, userData = {}) => {
  try {
    const ts = Math.floor(Date.now() / 1000).toString();
    const path = `/resources/applicants?levelName=${encodeURIComponent(LEVEL_NAME)}`;
    const method = 'POST';
    
    const requestBody = {
      externalUserId,
      info: {
        country: userData.country || 'USA',
        firstName: userData.name || '',
        lastName: userData.lastName || ''
      }
    };

    const signature = generateSignature(ts, method, path, requestBody);

    const headers = {
      'X-App-Token': SUMSUB_APP_TOKEN,
      'X-App-Access-Ts': ts,
      'X-App-Access-Sig': signature,
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    };

    const response = await axios.post(`${SUMSUB_BASE_URL}${path}`, requestBody, { 
      headers,
      timeout: 10000 
    });
    return response.data;
  } catch (error) {
    console.error('SumSub Create Applicant Error:', {
      status: error.response?.status,
      data: error.response?.data,
      config: error.config
    });
    throw error;
  }
};

const generateAccessToken = async (externalUserId) => {
  try {
    const ts = Math.floor(Date.now() / 1000).toString();
    const path = `/resources/accessTokens?userId=${encodeURIComponent(externalUserId)}&levelName=${encodeURIComponent(LEVEL_NAME)}`;
    const method = 'POST';

    // Critical fix: Pass undefined for body when not applicable
    const signature = generateSignature(ts, method, path, undefined);

    const headers = {
      'X-App-Token': SUMSUB_APP_TOKEN,
      'X-App-Access-Ts': ts,
      'X-App-Access-Sig': signature,
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    };

    // Critical fix: Use undefined instead of null for body
    const response = await axios.post(`${SUMSUB_BASE_URL}${path}`, undefined, { 
      headers,
      timeout: 10000 
    });
return response.data.token;

  } catch (error) {
    console.error('SumSub Token Error:', {
      status: error.response?.status,
      data: error.response?.data,
      config: error.config
    });
    
    if (error.response?.status === 404) {
      error.isApplicantNotFound = true;
    }
    throw error;
  }
};


const checkApplicantStatus = async (applicantId) => {
  try {
    const ts = Math.floor(Date.now() / 1000).toString();
    const path = `/resources/applicants/${applicantId}/one`;
    const method = 'GET';

    const signature = generateSignature(ts, method, path, undefined);

    const headers = {
      'X-App-Token': SUMSUB_APP_TOKEN,
      'X-App-Access-Ts': ts,
      'X-App-Access-Sig': signature,
      'Accept': 'application/json'
    };

    const response = await axios.get(`${SUMSUB_BASE_URL}${path}`, { headers });
    return response.data;
  } catch (error) {
    console.error('SumSub Status Check Error:', error.response?.data);
    throw error;
  }
};

module.exports = {
  createApplicant,
  generateAccessToken,
  generateVerificationToken,
  checkApplicantStatus
};