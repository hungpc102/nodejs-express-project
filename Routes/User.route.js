const express = require('express');
const route = express.Router();
const createError = require('http-errors')

const {vefifyAccessToken} = require('../helpers/jwt_service');
const UserController = require('../Controllers/User.controller')




route.post('/register', UserController.register);

route.post('/refresh-token', UserController.refreshToken)

route.post('/login', UserController.login);

route.delete('/logout', UserController.logout);

route.get('/getlists', vefifyAccessToken, UserController.getlists)

module.exports = route;
