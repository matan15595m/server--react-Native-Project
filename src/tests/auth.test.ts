import request from 'supertest'
import app from '../server'
import mongoose from 'mongoose'
import Post from '../models/post_model'
import User from '../models/user_model'

const userEmail = "user1@gmail.com"
const userPassword = "12345"
let accessToken = ''
let refreshToken = ''

beforeAll(async ()=>{
    await Post.remove()
    await User.remove()
})

afterAll(async ()=>{
    await Post.remove()
    await User.remove()
    mongoose.connection.close()
})

describe("Auth Tests", ()=>{
    test("Not aquthorized attempt test",async ()=>{
        const response = await request(app).get('/post');
        expect(response.statusCode).not.toEqual(200)
    })

    test("Register test",async ()=>{
        const response = await request(app).post('/auth/register').send({
            "email": userEmail,
            "password": userPassword 
        })
        expect(response.statusCode).toEqual(200)
    })

    test("Login test wrog password",async ()=>{
        const response = await request(app).post('/auth/login').send({
            "email": userEmail,
            "password": userPassword + '4'
        })
        expect(response.statusCode).not.toEqual(200)
        const access = response.body.accesstoken
        expect(access).toBeUndefined()
    })

    test("Login test",async ()=>{
        const response = await request(app).post('/auth/login').send({
            "email": userEmail,
            "password": userPassword 
        })
        expect(response.statusCode).toEqual(200)
        accessToken = response.body.accessToken
        expect(accessToken).not.toBeNull()
        refreshToken = response.body.refreshToken
        expect(refreshToken).not.toBeNull()
    })


    test("test sign valid access token",async ()=>{
        const response = await request(app).get('/post').set('Authorization', 'JWT ' + accessToken);
        expect(response.statusCode).toEqual(200)
    })

    test("test sign wrong access token",async ()=>{
        const response = await request(app).get('/post').set('Authorization', 'JWT 1' + accessToken);
        expect(response.statusCode).not.toEqual(200)
    })

    jest.setTimeout(15000)

    test("test expiered token",async ()=>{
        await new Promise(r => setTimeout(r,6000))
        const response = await request(app).get('/post').set('Authorization', 'JWT ' + accessToken);
        expect(response.statusCode).not.toEqual(200)
    })

    test("test refresh token",async ()=>{
        let response = await request(app).get('/auth/refresh').set('Authorization', 'JWT ' + refreshToken);
        expect(response.statusCode).toEqual(200)

        accessToken = response.body.accessToken
        expect(accessToken).not.toBeNull()
        refreshToken = response.body.refreshToken
        expect(refreshToken).not.toBeNull()
        
        response = await request(app).get('/post').set('Authorization', 'JWT ' + accessToken);
        expect(response.statusCode).toEqual(200)

    })

    test("Logout test",async ()=>{
        const response = await request(app).get('/auth/logout').set('Authorization', 'JWT ' + refreshToken)
        expect(response.statusCode).toEqual(200)
    })
    
})