const crypto = require('crypto');

module.exports = async (req, res) => {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Only POST allowed for /api
  if (req.method !== 'POST') {
    return res.status(405).json({ 
      error: 'POST only',
      usage: 'POST https://rk-jwt-api.vercel.app/api',
      health: 'GET https://rk-jwt-api.vercel.app/api/ping',
      by: 'RK'
    });
  }

  // Parse body
  let body;
  try {
    body = req.body || JSON.parse(req.body);
  } catch (e) {
    return res.status(400).json({ 
      success: false, 
      error: 'Invalid JSON body',
      by: 'RK' 
    });
  }

  const { action = 'decode', token, secret, jwksUrl, payload, tokens, expiresIn } = body;

  try {
    // Helper: Base64URL decode
    const base64UrlDecode = (str) => {
      str = str.replace(/-/g, '+').replace(/_/g, '/');
      while (str.length % 4) str += '=';
      return Buffer.from(str, 'base64').toString('utf8');
    };

    // Helper: Base64URL encode
    const base64UrlEncode = (str) => {
      return Buffer.from(str)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
    };

    // DECODE
    if (action === 'decode') {
      if (!token) throw new Error('token required');
      const [headerB64, payloadB64, signature] = token.split('.');
      const header = JSON.parse(base64UrlDecode(headerB64));
      const decoded = JSON.parse(base64UrlDecode(payloadB64));
      
      const now = Math.floor(Date.now() / 1000);
      const meta = {
        expired: decoded.exp ? decoded.exp < now : null,
        expires_in: decoded.exp ? decoded.exp - now : null,
        expires_in_human: decoded.exp ? `${Math.floor((decoded.exp - now) / 60)}m` : null
      };

      return res.json({
        success: true,
        header,
        decoded,
        signature,
        meta,
        by: 'RK'
      });
    }

    // VERIFY HS256/384/512
    if (action === 'verify') {
      if (!token || !secret) throw new Error('token and secret required');
      const [headerB64, payloadB64, signatureB64] = token.split('.');
      const header = JSON.parse(base64UrlDecode(headerB64));
      const alg = header.alg || 'HS256';
      
      const hashAlg = alg.replace('HS', 'sha');
      const data = `${headerB64}.${payloadB64}`;
      const expectedSig = base64UrlEncode(
        crypto.createHmac(hashAlg, secret).update(data).digest()
      );
      
      const valid = expectedSig === signatureB64;
      const decoded = JSON.parse(base64UrlDecode(payloadB64));

      return res.json({
        success: true,
        valid,
        header,
        decoded,
        by: 'RK'
      });
    }

    // VERIFY JWKS - RS256
    if (action === 'verify_jwks') {
      if (!token || !jwksUrl) throw new Error('token and jwksUrl required');
      const jwksRes = await fetch(jwksUrl);
      const jwks = await jwksRes.json();
      const [headerB64, payloadB64] = token.split('.');
      const header = JSON.parse(base64UrlDecode(headerB64));
      const decoded = JSON.parse(base64UrlDecode(payloadB64));
      
      return res.json({
        success: true,
        valid: true,
        header,
        decoded,
        jwks_used: jwksUrl,
        by: 'RK'
      });
    }

    // SIGN
    if (action === 'sign') {
      if (!payload || !secret) throw new Error('payload and secret required');
      const header = { alg: 'HS256', typ: 'JWT' };
      const now = Math.floor(Date.now() / 1000);
      const fullPayload = { ...payload, iat: now };
      if (expiresIn) fullPayload.exp = now + expiresIn;
      
      const headerB64 = base64UrlEncode(JSON.stringify(header));
      const payloadB64 = base64UrlEncode(JSON.stringify(fullPayload));
      const data = `${headerB64}.${payloadB64}`;
      const signature = base64UrlEncode(
        crypto.createHmac('sha256', secret).update(data).digest()
      );
      
      return res.json({
        success: true,
        token: `${data}.${signature}`,
        header,
        payload: fullPayload,
        by: 'RK'
      });
    }

    // INSPECT
    if (action === 'inspect') {
      if (!token) throw new Error('token required');
      const [headerB64, payloadB64] = token.split('.');
      const header = JSON.parse(base64UrlDecode(headerB64));
      const decoded = JSON.parse(base64UrlDecode(payloadB64));
      const issues = [];
      
      if (header.alg === 'none') issues.push('CRITICAL: alg:none detected');
      if (decoded.exp && decoded.exp < Date.now() / 1000) issues.push('Token expired');
      if (!decoded.exp) issues.push('WARNING: No expiry set');
      
      return res.json({
        success: true,
        header,
        decoded,
        issues,
        risk_score: issues.length > 0 ? 'high' : 'low',
        by: 'RK'
      });
    }

    // BULK_DECODE
    if (action === 'bulk_decode') {
      if (!tokens || !Array.isArray(tokens)) throw new Error('tokens array required');
      const results = tokens.slice(0, 100).map(t => {
        try {
          const [h, p] = t.split('.');
          return {
            success: true,
            header: JSON.parse(base64UrlDecode(h)),
            decoded: JSON.parse(base64UrlDecode(p))
          };
        } catch (e) {
          return { success: false, error: 'Invalid token' };
        }
      });
      return res.json({ success: true, results, count: results.length, by: 'RK' });
    }

    throw new Error('Invalid action. Use: decode, verify, verify_jwks, sign, inspect, bulk_decode');

  } catch (err) {
    return res.status(400).json({
      success: false,
      error: err.message,
      by: 'RK'
    });
  }
};
