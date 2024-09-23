const express = require('express');
const Datastore = require('nedb-promises');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('./config');
const { authenticator, totp } = require('otplib');
const qrcode = require('qrcode');
const crypto = require('crypto');
const NodeCache = require('node-cache');

const app = express();

app.use(express.json());
const cache = new NodeCache();

const usersDB = Datastore.create('Users.db');
const refreshTokensDB = Datastore.create('RefreshTokens.db');
const userInvalidTokensDB = Datastore.create('UserInvalidTokens.db');

app.get('/', (req, res) => {
    res.send('REST API Authentication and Authorization');
});

// TO DO List
// Check and sanitize user input (specially the password)
// Salt should be an environment variable
// Move middlewares to separate folder
app.post('/v1/auth/register', async (req, res) => {
    try {
        const { name, email, password, role } = req.body;

        if (!name || !email || !password) return res.status(422).json({ message: 'Please fill in all the fields (name, email, password)' });

        if (await usersDB.findOne({ email })) return res.status(409).json({ message: `The email ${email} is already registered` });

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await usersDB.insert({
            name,
            email,
            hashedPassword,
            role: role ?? 'member',
            '2faEnabled': false,
            '2faSecret': null,
        });

        return res.status(201).json({ message: 'User registered successfuly', id: newUser._id });
    }
    catch (error) {
        return res.status(500).json({ message: error.message })
    }
});

app.post('/v1/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) return res.status(422).json({ message: 'Please fill in all the fields (email, password)' });

        const user = await usersDB.findOne({ email });

        if (!user) return res.status(401).json({ message: 'Email or password invalid' });

        const passwordMatch = await bcrypt.compare(password, user.hashedPassword);

        if (!passwordMatch) return res.status(401).json({ message: 'Email or password invalid' });

        if (user['2faEnabled']) {
            const tempToken = crypto.randomUUID();

            cache.set(config.cacheTemporaryTokenPrefix + tempToken, user._id, config.cacheTemporaryTokenExpiration);

            return res.status(200).json({ tempToken, expiresInSeconds: config.cacheTemporaryTokenExpiration });
        }
        else {
            // Generate access token
            const accessToken = jwt.sign({ userId: user._id }, config.accessTokenSecret, { subject: 'apiAccessToken', expiresIn: config.accessTokenExpiration });
    
            // Generate refresh token
            const refreshToken = jwt.sign({ userId: user._id }, config.refreshTokenSecret, { subject: 'refreshToken', expiresIn: config.refreshTokenExpiration });
    
            //Save Refresh token on DB
            await refreshTokensDB.insert({
                refreshToken: refreshToken,
                userId: user._id
            });
    
            return res.status(200).json({
                message: 'Logged in successfully',
                id: user._id,
                name: user.name,
                email: user.email,
                accessToken,
                refreshToken
            });
        }
    }
    catch (error) {
        return res.status(500).json({ message: error.message, stack: error.stack });
    }
});

app.post('/v1/auth/login/2fa', async (req, res) => {
    try {
        const { tempToken, totp } = req.body;

        if (!tempToken || !totp) return res.status(422).json({ message: 'Please Fill In All Fields (tempToken and totp' });

        const userId = cache.get(config.cacheTemporaryTokenPrefix + tempToken);

        if (!userId) {
            return res.status(401).json({ message: 'Provided Temporary Token Is Incorrect Or Expired' });
        }

        const user = await usersDB.findOne({ _id: userId });

        const verified = authenticator.check(totp, user['2faSecret']);

        if (!verified) return res.status(401).json({ message: 'Provided TOTP Is Incorrect Or Expired' });

        // Generate access token
        const accessToken = jwt.sign({ userId: user._id }, config.accessTokenSecret, { subject: 'apiAccessToken', expiresIn: config.accessTokenExpiration });
    
        // Generate refresh token
        const refreshToken = jwt.sign({ userId: user._id }, config.refreshTokenSecret, { subject: 'refreshToken', expiresIn: config.refreshTokenExpiration });

        //Save Refresh token on DB
        await refreshTokensDB.insert({
            refreshToken: refreshToken,
            userId: user._id
        });

        return res.status(200).json({
            message: 'Logged in successfully',
            id: user._id,
            name: user.name,
            email: user.email,
            accessToken,
            refreshToken
        });
    } 
    catch (error) {
        return res.status(500).json({ message: error.message, stack: error.stack });
    }
});

app.post('/v1/auth/refresh', async (req, res) => {
    try {
        const { refreshToken } = req.body;

        if (!refreshToken) {
            return res.status(401).json({ message: 'Refresh Token Not Found' });
        }

        const decodedRefreshToken = jwt.verify(refreshToken, config.refreshTokenSecret);
        
        const userRefreshToken = await refreshTokensDB.findOne({ userId: decodedRefreshToken.userId });

        if (!userRefreshToken) return res.status(401).json({ message: 'Refresh Token Invalid Or Expired' });

        await refreshTokensDB.remove({ _id: refreshTokensDB._id });
        await refreshTokensDB.compactDatafile();

        // Generate access token
        const accessToken = jwt.sign({ userId: decodedRefreshToken.userId }, config.accessTokenSecret, { subject: 'apiAccessToken', expiresIn: config.accessTokenExpiration });

        // Generate refresh token
        const newRefreshToken = jwt.sign({ userId: decodedRefreshToken.userId }, config.refreshTokenSecret, { subject: 'refreshToken', expiresIn: config.refreshTokenExpiration });

        //Save Refresh token on DB
        await refreshTokensDB.insert({
            refreshToken: newRefreshToken,
            userId: decodedRefreshToken.userId
        });

        return res.status(200).json({
            accessToken,
            refreshToken: newRefreshToken
        });
    }
    catch (error) {
        if (error instanceof jwt.TokenExpiredError || error instanceof jwt.JsonWebTokenError) {
            console.log(error.stack);
            return res.status(401).json({ message: 'Refresh Token Invalid Or Expired' });
        }

        return res.status(500).json({ message: error.message });
    }
});

app.get('/v1/auth/2fa/generate', ensureAuthenticated, async (req, res) => {
    try {
        // Retrieve user information
        const user = await usersDB.findOne({ _id: req.user.id });
        
        // Generate Secret
        const secret = authenticator.generateSecret();
        
        //Issue URI for QR code
        const uri = authenticator.keyuri(user.email, 'City Of Rocky Mount', secret);
        await usersDB.update({ _id: req.user.id }, { $set: { '2faSecret': secret  } });
        await usersDB.compactDatafile();

        //Generate QR Code Image
        const qrCode = await qrcode.toBuffer(uri, { type: 'image/png', margin: 1 });
        
        res.setHeader('Content-Disposition', 'attachment; filename=qrcode.png');
        return res.status(200).type('image/png').send(qrCode);
    } 
    catch (error) {
        return res.status(500).json({ message: error.message });
    }
});

app.post('/v1/auth/2fa/validate', ensureAuthenticated, async(req, res) => {
    try {
        const { totp } = req.body;

        if(!totp) return res.status(422).json({ message: 'Time Based One Time Password (TOTP) Is Required' });

        const user = await usersDB.findOne({ _id: req.user.id });

        const verified = authenticator.check(totp, user['2faSecret']);

        if (!verified) return res.status(400).json({ message: 'Time Based One Time Password (TOTP) Is Not Valid or Expired' });

        await usersDB.update({ _id: req.user.id }, {$set: { '2faEnabled': true }});
        await usersDB.compactDatafile();

        return res.status(200).json({ message: 'Time Based One Time Password (TOTP) Validated' })
    } 
    catch (error) {
        return res.status(500).json({ message: error.message });
    }
});

app.get('/v1/auth/logout', ensureAuthenticated, async (req, res) => {
    try {
        await refreshTokensDB.removeMany({ userId: req.user.id });
        await refreshTokensDB.compactDatafile();

        await userInvalidTokensDB.insert({
            accessToken: req.accessToken.value,
            userId: req.user.id,
            expirationTime: req.accessToken.exp
        })

        return res.status(204).send();
    } 
    catch (error) {
        return res.status(500).json({ message: error.message });
    }
})

app.get('/v1/users/current', ensureAuthenticated, async (req, res) => {
    try {
        const user = await usersDB.findOne({ _id: req.user.id });

        if (!user) return res.status(401).json({ message: 'User Not Authenticated, Login With Your Account' });

        return res.status(200).json({ id: user._id, name: user.name, email: user.email });
    }
    catch (error) {
        return res.status(500).json({ message: error.message, stack: error.stack })
    }
});

app.get('/v1/admin', ensureAuthenticated, ensureAuthorized(['admin']), (req, res) => {
    return res.status(200).json({ message: 'Only Administrators Can Access This Route' })
});

app.get('/v1/moderator', ensureAuthenticated, ensureAuthorized(['admin', 'moderator']), (req, res) => {
    return res.status(200).json({ message: 'Only Administrators And Moderators Can Access This Route' })
});

async function ensureAuthenticated (req, res, next) {
    const accessToken = req.headers.authorization;
    
    if (!accessToken) {
        return res.status(401).json({ message: 'Access Token Not Found' })
    }
    
    if (await userInvalidTokensDB.findOne({ accessToken: accessToken })) {
        return res.status(401).json({message: 'Access Token Invalid', code: 'AccessTokenInvalid'});
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

function ensureAuthorized(roles = []) {
    return async function (req, res, next) {
        const user = await usersDB.findOne({ _id: req.user.id });

        if (!user || !roles.includes(user.role)) {
            return res.status(403).json({ message: 'Access Denied' });
        }

        next();
    }
}

app.listen(3000, () => console.log('Server running on port 3000...'));
