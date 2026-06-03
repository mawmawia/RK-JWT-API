module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'GET only', by: 'RK' });
  }
  
  return res.status(200).json({
    status: 'ok',
    service: 'RK JWT API #003',
    version: 'v1',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    by: 'RK'
  });
};
