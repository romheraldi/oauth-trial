const express = require('express')
const app = express()
const port = 3000
const crypto = require('crypto')
const fs = require('fs')
const oauth2orize = require('oauth2orize')
const passport = require('passport')

app.use(express.urlencoded({extended: false}))
app.use(express.json())
app.use(passport.initialize())

const server = oauth2orize.createServer();

const clients = [
    { id: 1, clientId: '123-456-789', clientSecret: '987-654-321', name: 'John Doe' },
    { id: 2, clientId: '012-345-678', clientSecret: '876-543-210', name: 'Jane Doe' },
]

const getClientPublicKey = () => {
    return fs.readFileSync('public-key.pem', 'utf-8')
}

const verifyTokenMiddleware = (req, res, next) => {
    console.log(req.headers)
    const clientSignature = req.headers['x-signature']
    const clientId = req.headers['x-client-id']
    const timestamp = req.headers['x-timestamp']
    const stringToSign = `${clientId}|${timestamp}`

    const clientPublicKey = getClientPublicKey()

    const verify = crypto.createVerify('SHA256')

    verify.update(stringToSign)

    if (!verify.verify(clientPublicKey, clientSignature, 'base64')) {
        return res.status(401).json({ error: 'Signature verification failed' })
    }

    next()
}

app.get('/', (req, res) => {
    res.send('Hello world!, this is IKAN server')
})

app.post('/v1.0/access-token/b2b', verifyTokenMiddleware, (req, res) => {
    const responseData = {
        responseCode: '2007300',
        responseMessage: 'Successful',
        accessToken: '7t4tbXnlyn4NABRn0FAhB69CRhxghlPPfPK2l9quE29l4D4k5DLH57',
        tokenType: 'bearer',
        expiresIn: '900',
    }

    res.json(responseData)
})

app.get('/protected', (req, res) => {
    return res.json({ message: 'Protected route' })
})

server.exchange()

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
