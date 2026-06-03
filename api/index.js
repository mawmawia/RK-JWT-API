import { jwtVerify, SignJWT, decodeJwt, createRemoteJWKSet } from 'jose';
import jwt from 'jsonwebtoken';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('X-Powered-By', 'RK-JWT-API v2 | Rael_Kertia Empire');
  
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method!== 'POST') return res.status(405).json({ error: 'POST only', by: 'RK' });

  const { action, token, tokens, secret, payload, alg = 'HS256', expiresIn, jwksUrl, preset } = req.body;

  try {
    if (action === 'decode') {
      const decoded = decodeJwt(token);
      const now = Math.floor(Date.now() / 1000);
      const exp = decoded.exp || 0;
      return res.json({ 
        success: true, 
        decoded,
        meta: {
          expired: exp < now,
          expires_in_seconds: exp - now,
          expires_in_human: exp? `${Math.floor((exp - now) / 60)}m` : null
        },
        by: 'RK' 
      });
    }

    if (action === 'bulk_decode') {
      const results = tokens.map(t => {
        try {
          return { token: t.slice(0,20) + '...', decoded: decodeJwt(t), error: null }
        } catch(e) {
          return { token: t.slice(0,20) + '...', decoded: null, error: e.message }
        }
      });
      return res.json({ success: true, count: results.length, results, by: 'RK' });
    }

    if (action === 'verify_jwks') {
      const JWKS = createRemoteJWKSet(new URL(jwksUrl));
      const { payload: verified, protectedHeader } = await jwtVerify(token, JWKS);
      return res.json({ 
        success: true, 
        valid: true, 
        payload: verified,
        header: protectedHeader,
        by: 'RK' 
      });
    }

    if (action === 'verify') {
      const secretKey = new TextEncoder().encode(secret);
      const { payload: verified } = await jwtVerify(token, secretKey);
      return res.json({ success: true, valid: true, payload: verified, by: 'RK' });
    }

    if (action === 'sign') {
      let finalPayload = payload;
      if (preset === 'auth0_test') {
        finalPayload = { sub: 'test-user', aud: 'api', iss: 'https://rk-jwt', scope: 'read:all' };
      }
      if (preset === 'firebase') {
        finalPayload = { uid: 'test-uid', email: 'test@rk.com', email_verified: true };
      }
      
      if (alg.startsWith('HS')) {
        const signed = jwt.sign(finalPayload, secret, { algorithm: alg, expiresIn });
        return res.json({ success: true, token: signed, by: 'RK' });
      }
      const secretKey = new TextEncoder().encode(secret);
      const signed = await new SignJWT(finalPayload)
       .setProtectedHeader({ alg })
       .setExpirationTime(expiresIn || '1h')
       .sign(secretKey);
      return res.json({ success: true, token: signed, by: 'RK' });
    }

    if (action === 'inspect') {
      const decoded = decodeJwt(token);
      const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString());
      const warnings = [];
      if (header.alg === 'none') warnings.push('CRITICAL: alg:none detected');
      if (header.alg.startsWith('HS') && secret?.length < 32) warnings.push('WARNING: Secret < 32 chars');
      if (!decoded.exp) warnings.push('WARNING: No expiry set');
      
      return res.json({ 
        success: true, 
        header,
        payload: decoded,
        security_warnings: warnings,
        score: warnings.length === 0? 'A+' : warnings.length < 2? 'B' : 'F',
        by: 'RK' 
      });
    }

    return res.status(400).json({ error: 'Invalid action. Use: decode, bulk_decode, verify, verify_jwks, sign, inspect', by: 'RK' });
  } catch (e) {
    return res.status(400).json({ success: false, error: e.message, by: 'RK' });
  }
}
