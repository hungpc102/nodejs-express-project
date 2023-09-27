const express = require('express');
const route = express.Router();
const createError = require('http-errors')

const UserSchema = require('../Models/User.model')
const {userValidate} =  require('../helpers/validation')
const {signAccessToken, vefifyAccessToken, signRefreshToken} = require('../helpers/jwt_service')

route.post('/register', async (req, res, next) => {
    
    try{
        const {USER_NAME ,USER_PHONE, USER_EMAIL, USER_PASSWORD} =req.body
        const {error}= userValidate(req.body, isRegister = true)
        console.log(`::::::::error validation`, error)
        if(error){
            throw createError(error.details[0].message)
        }

        const isExits = await UserSchema.findOne({
            where: {USER_EMAIL}
        })

        if(isExits){
            throw createError.Conflict(`${USER_EMAIL} has ready been registered`)
        }

        const user = new UserSchema({
            USER_EMAIL,
            USER_PASSWORD,
            USER_NAME,
            USER_PHONE
        })
        const saveUser = await user.save()

        return res.json({
            status: 'okay',
            elements: saveUser
        })

    } catch(error){
        // console.error(error); 
        next(error)
    }
});

route.post('/refresh-token', (req, res, next) => {
    res.send('/Function refresh-token');
});

route.post('/login',async (req, res, next) => {

    try{
        const {error}= userValidate(req.body,isRegister = false)
        if(error){
            throw createError(error.details[0].message)
        }
        const{USER_EMAIL, USER_PASSWORD} = req.body

        const user = await UserSchema.findOne({
            where: {USER_EMAIL}
        })
        if(!user){
            throw createError.NotFound('User not resgistered')
        }
        const isValid = await user.isCheckPassword(USER_PASSWORD)

        if(!isValid){
            throw createError.Unauthorized()
        }

        const accessToken = await signAccessToken(user.USER_ID)
        const refreshToken =  await signRefreshToken(user.USER_ID)
        res.json({
            accessToken,
            refreshToken
        });

    } catch(error){
        next(error)
    }
});

route.post('/logout', (req, res, next) => {

    res.send('/Function logout');
});

route.get('/getlists', vefifyAccessToken, async(req, res, next) => {
    console.log(req.headers)
    const listUsers = [
        {
        email: 'abc@gmail.com'
        },
        {
        email: 'def@gmail.com'
        }
    ]
    res.json({
        listUsers
    })
})

module.exports = route;
