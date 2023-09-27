const JWT = require ('jsonwebtoken')
const createError = require("http-errors")

const signAccessToken = async (userId) =>{
    return new Promise((resolve, reject) => {
        const payLoad = {
            userId
        }
        const secret = process.env.ACCESS_TOKEN_SECRET
        const options = {
            expiresIn: '10s' // 10m 10s
        }

        JWT.sign(payLoad, secret, options, (err, token) => {
            if(err){
                reject(err);
            } 
            resolve(token)
        })
    })
}

const vefifyAccessToken = (req, res, next) => {
    if(!req.headers['authorization']){
        return next(createError.Unauthorized())
    }
    const authHeader = req.headers['authorization']
    const bearerToken = authHeader.split(' ')
    const token = bearerToken[1]
    // start verify token
    JWT.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, payLoad ) => {
        if(err){
            return next(createError.Unauthorized())
        }
        req.payLoad = payLoad
        next()
    })

}

const signRefreshToken = async (userId) =>{
    return new Promise((resolve, reject) => {
        const payLoad = {
            userId
        }
        const secret = process.env.REFRESH_TOKEN_SECRET
        const options = {
            expiresIn: '1y' // 10m 10s
        }

        JWT.sign(payLoad, secret, options, (err, token) => {
            if(err){
                reject(err);
            } 
            resolve(token)
        })
    })
}

module.exports = {
    signAccessToken,
    vefifyAccessToken,
    signRefreshToken
}