const express = require('express')
const app = express()
const port = 3001
const axios = require('axios')
const fs = require('fs')
const crypto = require('crypto')

const credential = { clientId: '123-456-789', clientSecret: '987-654-321' }

const getPrivateKey = () => {
    return fs.readFileSync('private-key.pem', 'utf-8')
}

const minifyAndHash = data => {
    const jsonString = JSON.stringify(data)
    const minifiedString = jsonString.replace(/\s/g, '') // Remove whitespaces for minification
    const sha256 = crypto.createHash('sha256').update(minifiedString).digest('hex')
    return sha256
}

app.get('/', async (req, res) => {
    const timeStamp = new Date().toISOString()
    const privateKey = getPrivateKey()
    const stringToSign = `${credential.clientId}|${timeStamp}`
    const sign = crypto.createSign('RSA-SHA256')
    sign.update(stringToSign)
    const signature = sign.sign(privateKey, 'base64')

    const headers = {
        'X-TIMESTAMP': timeStamp,
        'X-CLIENT-ID': credential.clientId,
        'X-SIGNATURE': signature,
    }

    axios
        .post('http://localhost:3000/v1.0/access-token/b2b', { grantType: 'client_credentials' }, { headers: headers })
        .then(response => {
            const getTimeStamp = new Date().toISOString()
            const secretKey = credential.clientSecret
            const contentType = 'application/json'
            const dataBody = {
                message: 'Hello world!, this is protected route',
            }
            const relativeUrl = '/protected'
            const httpMethod = 'POST'
            const accessToken = response.data.accessToken
            const stringToSign = `${httpMethod}:${relativeUrl}:${accessToken}:${minifyAndHash(
                dataBody
            )}:${getTimeStamp}`

            console.log(stringToSign)

            const sign = crypto.createHmac('sha512', secretKey).update(stringToSign).digest('base64')

            axios
                .post('http://localhost:3000/protected', dataBody, {
                    headers: {
                        'x-timestamp': getTimeStamp,
                        'x-signature': sign,
                        'Content-Type': contentType,
                        authorization: `Bearer ${response.data.accessToken}`,
                    },
                })
                .then(resGet => res.json(resGet.data))
                .catch(errGet => res.json(errGet.response.data))
        })
        .catch(err => res.json(err.message))
})

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
