
require('dotenv').config();
const jwt = require('jsonwebtoken');
const expiration = '2h';
const secret = process.env.MY_SECRET;


module.exports = {
    signToken: function ({ username, email, _id }) {
        const payload = { username, email, _id };
        // console.log("MY_SECRET: ", secret);
        return jwt.sign({ data: payload }, secret, { expiresIn: expiration });
    },

    authMiddleware: function({ req }) {
        // allows token to be sent via req.body, req.query, or headers
        let token = req.body.token || req.query.token || req.headers.authorization;

        // separate "Bearer" from "<tokenvalue>"
        if(req.headers.authorization) {
            token = token
                .split(' ')
                .pop()
                .trim();
        }

        // if no token, return request object as is
        if(!token) {
            return req;
        }

        try {
            // decode and attach user data to requet object
            const { data } = jwt.verify(token, secret, { maxAge: expiration});
            req.user = data; 
        } catch {
            console.log('Invalid token');
        }

        // return updated request object
        return req;
    }
};