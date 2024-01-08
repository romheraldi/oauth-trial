const express = require('express')
const app = express()
const port = 3000
const crypto = require('crypto')
const fs = require('fs')
const jwt = require('jsonwebtoken')

const jwtSecret =
    '09f26e402586e2faa8da4c98a35f1b20d6b033c6097befa8be3486a829587fe2f90a832bd3ff9d42710a4da095a2ce285b009f0c3730cd9b8e1af3eb84df6611'

app.use(express.urlencoded({ extended: true }))
app.use(express.json())

const clients = [
    { clientId: '123-456-789', clientSecret: '987-654-321', name: 'John Doe' },
    { clientId: '012-345-678', clientSecret: '876-543-210', name: 'Jane Doe' },
]

const getClientPublicKey = () => {
    return fs.readFileSync('public-key.pem', 'utf-8')
}

const verifyTokenMiddleware = (req, res, next) => {
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

const minifyAndHash = data => {
    console.log(data)
    const jsonString = JSON.stringify(data)
    const minifiedString = jsonString.replace(/\s/g, '') // Remove whitespaces for minification
    const sha256 = crypto.createHash('sha256').update(minifiedString).digest('hex')
    return sha256
}

const authenticateUser = (req, res, next) => {
    const authHeader = req.headers['authorization']
    const clientSignature = req.headers['x-signature']
    const timestamp = req.headers['x-timestamp']
    const relativeUrl = req.originalUrl
    const method = req.method.toUpperCase()

    const token = authHeader && authHeader.split(' ')[1]

    if (token == null) return res.status(401).json({ error: 'Unauthenticated token not found' })
    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) return res.status(403).json({ error: 'Unauthenticated Wrong JWT' })

        const stringToSign = `${method}:${relativeUrl}:${token}:${minifyAndHash(req.body)}:${timestamp}`

        console.log(stringToSign)

        const client = clients.find(client => client.clientId === user.clientId)
        const clientSecret = client.clientSecret

        const verify = crypto.createHmac('sha512', clientSecret).update(stringToSign).digest('base64')

        if (verify !== clientSignature) {
            return res.status(401).json({ error: 'Signature failed' })
        }

        next()
    })
}

app.get('/', (req, res) => {
    res.send('Hello world!, this is IKAN server')
})

app.post('/v1.0/access-token/b2b', verifyTokenMiddleware, (req, res) => {
    const user = clients.find(client => client.clientId === req.headers['x-client-id'])
    if (!user) {
        res.status(401).json({ error: 'Unknown client' })
    }

    const { clientSecret, ...client } = user
    const token = jwt.sign(client, jwtSecret, { expiresIn: '900s' })

    const responseData = {
        responseCode: '2007300',
        responseMessage: 'Successful',
        accessToken: token,
        tokenType: 'bearer',
        expiresIn: '900',
    }

    res.json(responseData)
})

app.post('/protected', authenticateUser, (req, res) => {
    return res.json(req.body)
})

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
