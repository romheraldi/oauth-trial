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
            axios
                .get('http://localhost:3000/protected', {
                    headers: { authorization: `Bearer ${response.data.accessToken}` },
                })
                .then(resGet => res.json(resGet.data))
                .catch(errGet => res.json(errGet.response.data))
        })
        .catch(err => res.json(err.response.data))
})

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
