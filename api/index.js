const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

module.exports = async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Content-Type', 'application/json');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') {
    return res.status(405).json({ 
      error: 'POST only',
      usage: 'POST https://rk-jwt-api.vercel.app/api with JSON body',
      example: { action: 'decode', token: 'eyJ...' },
      by: 'RK' 
    });
  }

  try {
    // Default to 'decode' if no action provided
    const body = req.body || {};
    const { action = 'decode', token, tokens, secret, jwksUrl, payload, options } = body;

    // Validate token exists for actions that need it
    const needsToken = ['decode', 'verify', 'verify_jwks', 'inspect'];
    if (needsToken.includes(action) && !token) {
      return res.status(400).json({
        error: `Missing 'token' for action: ${action}`,
        usage: `POST { "action": "${action}", "token": "eyJ..." }`,
        valid_actions: ['decode', 'bulk_decode', 'verify', 'verify_jwks', 'sign', 'inspect'],
        by: 'RK'
      });
    }

    let result;

    switch (action) {
      case 'decode': {
        const decoded = jwt.decode(token, { complete: true });
        if (!decoded) throw new Error('Invalid JWT format - not a valid token');

        const now = Math.floor(Date.now() / 1000);
        const exp = decoded.payload.exp;
        const expired = exp ? now > exp : false;
        const expiresIn = exp ? exp - now : null;

        result = {
          decoded: decoded.payload,
          header: decoded.header,
          signature: decoded.signature,
          meta: {
            expired,
            expires_in_seconds: expiresIn,
            expires_in_human: formatTime(expiresIn),
            issued_at: decoded.payload.iat ? new Date(decoded.payload.iat * 1000).toISOString() : null,
            expires_at: exp ? new Date(exp * 1000).toISOString() : null
          }
        };
        break;
      }

      case 'verify': {
        if (!secret) throw new Error("Missing 'secret' for verify action");
        const verified = jwt.verify(token, secret, options || {});
        result = { 
          verified,
          valid: true
        };
        break;
      }

      case 'verify_jwks': {
        if (!jwksUrl) throw new Error("Missing 'jwksUrl' for verify_jwks action");
        
        const client = jwksClient({
          jwksUri: jwksUrl,
          cache: true,
          rateLimit: true,
          jwksRequestsPerMinute: 10
        });

        const getKey = (header, callback) => {
          client.getSigningKey(header.kid, (err, key) => {
            if (err) return callback(err);
            const signingKey = key?.publicKey || key?.rsaPublicKey;
            callback(null, signingKey);
          });
        };

        const verified = await new Promise((resolve, reject) => {
          jwt.verify(token, getKey, options || {}, (err, decoded) => {
            if (err) reject(new Error(`JWKS verification failed: ${err.message}`));
            else resolve(decoded);
          });
        });

        result = { 
          verified,
          valid: true,
          jwks_url: jwksUrl
        };
        break;
      }

      case 'sign': {
        if (!payload) throw new Error("Missing 'payload' for sign action");
        
        let signSecret = secret;
        if (options?.preset === 'auth0_test') signSecret = 'your-256-bit-secret';
        if (options?.preset === 'firebase') signSecret = 'firebase-secret';
        if (!signSecret) throw new Error("Missing 'secret' or valid preset for sign action");
        
        const signOptions = options?.jwt || { algorithm: 'HS256', expiresIn: '1h' };
        const newToken = jwt.sign(payload, signSecret, signOptions);
        
        result = { 
          token: newToken,
          decoded: jwt.decode(newToken, { complete: true })
        };
        break;
      }

      case 'inspect': {
        const inspected = jwt.decode(token, { complete: true });
        if (!inspected) throw new Error('Invalid JWT format - not a valid token');
        
        const issues = [];
        const header = inspected.header;
        const payload = inspected.payload;
        
        // Security checks
        if (header.alg === 'none') issues.push({ level: 'CRITICAL', msg: 'alg:none allows unsigned tokens - reject immediately' });
        if (header.alg.startsWith('HS') && !secret) issues.push({ level: 'INFO', msg: 'HS algorithm used - provide secret to verify signature' });
        if (!payload.exp) issues.push({ level: 'WARNING', msg: 'No expiry claim - token never expires' });
        if (payload.exp && payload.exp < Date.now() / 1000) issues.push({ level: 'WARNING', msg: 'Token is expired' });
        if (!payload.iat) issues.push({ level: 'INFO', msg: 'No issued-at claim' });
        if (!payload.aud) issues.push({ level: 'INFO', msg: 'No audience claim' });
        
        result = {
          header,
          payload,
          security_audit: {
            issues,
            risk_level: issues.some(i => i.level === 'CRITICAL') ? 'CRITICAL' : issues.some(i => i.level === 'WARNING') ? 'MEDIUM' : 'LOW',
            safe_to_use: !issues.some(i => i.level === 'CRITICAL')
          }
        };
        break;
      }

      case 'bulk_decode': {
        const tokenArray = tokens || token;
        if (!Array.isArray(tokenArray)) {
          throw new Error("bulk_decode expects 'tokens' or 'token' to be an array");
        }
        
        result = {
          count: tokenArray.length,
          results: tokenArray.map((t, idx) => {
            try {
              const d = jwt.decode(t, { complete: true });
              if (!d) throw new Error('Invalid format');
              return { 
                index: idx,
                success: true, 
                decoded: d.payload, 
                header: d.header,
                expired: d.payload.exp ? Date.now() / 1000 > d.payload.exp : null
              };
            } catch (e) {
              return { 
                index: idx,
                success: false, 
                error: e.message 
              };
            }
          })
        };
        break;
      }

      default:
        return res.status(400).json({
          error: `Invalid action: ${action}`,
          usage: 'POST { "action": "decode", "token": "eyJ..." }',
          valid_actions: ['decode', 'bulk_decode', 'verify', 'verify_jwks', 'sign', 'inspect'],
          by: 'RK'
        });
    }

    res.status(200).json({ 
      success: true, 
      ...result, 
      by: 'RK' 
    });

  } catch (error) {
    res.status(400).json({
      error: error.message,
      usage: 'POST { "action": "decode", "token": "eyJ..." }',
      docs: 'https://github.com/mawmav/rk-jwt-api',
      by: 'RK'
    });
  }
};

function formatTime(seconds) {
  if (seconds === null || seconds === undefined) return null;
  const abs = Math.abs(seconds);
  const sign = seconds < 0 ? '-' : '';
  if (abs < 60) return `${sign}${abs}s`;
  if (abs < 3600) return `${sign}${Math.floor(abs / 60)}m ${abs % 60}s`;
  if (abs < 86400) return `${sign}${Math.floor(abs / 3600)}h ${Math.floor((abs % 3600) / 60)}m`;
  return `${sign}${Math.floor(abs / 86400)}d ${Math.floor((abs % 86400) / 3600)}h`;
}
