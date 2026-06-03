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
      usage: 'POST https://rk-jwt-api.vercel.app/api',
      example: { action: 'decode', token: 'eyJ...' },
      by: 'RK' 
    });
  }

  // Parse body safely for Vercel
  let body = {};
  try {
    body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body || {};
  } catch (e) {
    return res.status(400).json({ error: 'Invalid JSON body', by: 'RK' });
  }

  try {
    const { action = 'decode', token, tokens, secret, jwksUrl, payload, options } = body;

    // Validate token exists for actions that need it
    const needsToken = ['decode', 'verify', 'verify_jwks', 'inspect'];
    if (needsToken.includes(action) && !token) {
      return res.status(400).json({
        error: `Missing 'token' for action: ${action}`,
        usage: { action: action, token: 'eyJ...' },
        valid_actions: ['decode', 'bulk_decode', 'verify', 'verify_jwks', 'sign', 'inspect'],
        by: 'RK'
      });
    }

    let result;

    switch (action) {
      case 'decode': {
        const decoded = jwt.decode(token, { complete: true });
        if (!decoded) throw new Error('Invalid JWT format');

        const now = Math.floor(Date.now() / 1000);
        const exp = decoded.payload.exp;
        const iat = decoded.payload.iat;
        
        result = {
          decoded: decoded.payload,
          header: decoded.header,
          meta: {
            expired: exp ? now > exp : false,
            expires_in_seconds: exp ? exp - now : null,
            expires_in_human: exp ? formatTime(exp - now) : null,
            issued_at: iat ? new Date(iat * 1000).toISOString() : null,
            expires_at: exp ? new Date(exp * 1000).toISOString() : null
          }
        };
        break;
      }

      case 'verify': {
        if (!secret) throw new Error("Missing 'secret' for verify");
        const verified = jwt.verify(token, secret, options || {});
        result = { verified, valid: true };
        break;
      }

      case 'verify_jwks': {
        if (!jwksUrl) throw new Error("Missing 'jwksUrl' for verify_jwks");
        
        const client = jwksClient({
          jwksUri: jwksUrl,
          cache: true,
          rateLimit: true
        });

        const getKey = (header, callback) => {
          client.getSigningKey(header.kid, (err, key) => {
            if (err) return callback(err);
            callback(null, key?.publicKey || key?.rsaPublicKey);
          });
        };

        const verified = await new Promise((resolve, reject) => {
          jwt.verify(token, getKey, options || {}, (err, decoded) => {
            if (err) reject(new Error(`JWKS verification failed: ${err.message}`));
            else resolve(decoded);
          });
        });

        result = { verified, valid: true, jwks_url: jwksUrl };
        break;
      }

      case 'sign': {
        if (!payload) throw new Error("Missing 'payload' for sign");
        
        let signSecret = secret;
        if (options?.preset === 'auth0_test') signSecret = 'your-256-bit-secret';
        if (options?.preset === 'firebase') signSecret = 'firebase-secret';
        if (!signSecret) throw new Error("Missing 'secret' or preset");
        
        const newToken = jwt.sign(payload, signSecret, options?.jwt || { algorithm: 'HS256', expiresIn: '1h' });
        result = { token: newToken, decoded: jwt.decode(newToken, { complete: true }) };
        break;
      }

      case 'inspect': {
        const inspected = jwt.decode(token, { complete: true });
        if (!inspected) throw new Error('Invalid JWT format');
        
        const issues = [];
        const h = inspected.header;
        const p = inspected.payload;
        
        if (h.alg === 'none') issues.push({ level: 'CRITICAL', msg: 'alg:none allows unsigned tokens' });
        if (!p.exp) issues.push({ level: 'WARNING', msg: 'No expiry claim' });
        if (p.exp && p.exp < Date.now() / 1000) issues.push({ level: 'WARNING', msg: 'Token expired' });
        if (h.alg.startsWith('HS') && !secret) issues.push({ level: 'INFO', msg: 'HS algorithm - provide secret to verify' });
        
        result = {
          header: h,
          payload: p,
          security_audit: {
            issues,
            risk_level: issues.some(i => i.level === 'CRITICAL') ? 'CRITICAL' : issues.some(i => i.level === 'WARNING') ? 'MEDIUM' : 'LOW',
            safe: !issues.some(i => i.level === 'CRITICAL')
          }
        };
        break;
      }

      case 'bulk_decode': {
        const tokenArray = tokens || token;
        if (!Array.isArray(tokenArray)) throw new Error("bulk_decode expects 'tokens' array");
        
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
                expired: d.payload.exp ? Date.now() / 1000 > d.payload.exp : null
              };
            } catch (e) {
              return { index: idx, success: false, error: e.message };
            }
          })
        };
        break;
      }

      default:
        return res.status(400).json({
          error: `Invalid action: ${action}`,
          valid_actions: ['decode', 'bulk_decode', 'verify', 'verify_jwks', 'sign', 'inspect'],
          by: 'RK'
        });
    }

    res.status(200).json({ success: true, ...result, by: 'RK' });

  } catch (error) {
    res.status(400).json({
      error: error.message,
      usage: { action: 'decode', token: 'eyJ...' },
      by: 'RK'
    });
  }
};

function formatTime(seconds) {
  if (seconds === null || seconds === undefined) return null;
  const abs = Math.abs(seconds);
  const sign = seconds < 0 ? '-' : '';
  if (abs < 60) return `${sign}${abs}s`;
  if (abs < 3600) return `${sign}${Math.floor(abs / 60)}m`;
  if (abs < 86400) return `${sign}${Math.floor(abs / 3600)}h`;
  return `${sign}${Math.floor(abs / 86400)}d`;
}
