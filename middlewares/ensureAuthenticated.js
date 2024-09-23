const jwt = require('jsonwebtoken')
const config = require('../config');

async function ensureAuthenticated (req, res, next) {
    const accessToken = req.headers.authorization;
    
    if (!accessToken) {
        return res.status(401).json({ message: 'Access Token Not Found' })
    }
    
    try {
        const decodedAccessToken = jwt.verify(accessToken, config.accessTokenSecret);
        
        req.accessToken = { value: accessToken, exp: decodedAccessToken.exp }
        req.user = { id: decodedAccessToken.userId }

        next();
    } 
    catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            return res.status(401).json({ message: 'Access Token Has Expired, Log In Again', code: 'AccessTokenExpired' });
        }
        else if (error instanceof jwt.JsonWebTokenError) {
            return res.status(401).json({ message: 'Access Token Invalid', code: 'AccessTokenInvalid' });
        }
        else {
            return res.status(500).json({ message: 'Internal Server Error', code: 'InternalServerError' });
        }
    }
}

module.exports = { ensureAuthenticated };
