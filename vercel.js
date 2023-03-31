"use strict"

const crypto = require('crypto')

let iv = '@@@@&&&&####$$$$'

const encrypt = (input, key) => {
    var cipher = crypto.createCipheriv('AES-128-CBC', key, iv)
    var encrypted = cipher.update(input, 'binary', 'base64')
    encrypted += cipher.final('base64')
    return encrypted
}

const decrypt = (encrypted, key) => {
    var decipher = crypto.createDecipheriv('AES-128-CBC', key, iv)
    var decrypted = decipher.update(encrypted, 'base64', 'binary')
    try {
        decrypted += decipher.final('binary')
    } catch (e) {
        console.log(e)
    }
    return decrypted
}

const generateSignature = (params, key) => {
    if (typeof params !== "object" && typeof params !== "string") {
        var error = "string or object expected, " + (typeof params) + " given."
        return Promise.reject(error)
    }
    if (typeof params !== "string") {
        params = getStringByParams(params)
    }
    return generateSignatureByString(params, key)
}


const verifySignature = (params, key, checksum) => {
    if (typeof params !== "object" && typeof params !== "string") {
        var error = "string or object expected, " + (typeof params) + " given."
        return Promise.reject(error)
    }
    if (params.hasOwnProperty("CHECKSUMHASH")) {
        delete params.CHECKSUMHASH
    }
    if (typeof params !== "string") {
        params = getStringByParams(params)
    }
    return verifySignatureByString(params, key, checksum)
}

const generateSignatureByString = async (params, key) => {
    var salt = await generateRandomString(4)
    return calculateChecksum(params, key, salt)
}


const verifySignatureByString = (params, key, checksum) => {
    var paytm_hash = decrypt(checksum, key)
    var salt = paytm_hash.substr(paytm_hash.length - 4)
    return (paytm_hash === calculateHash(params, salt))
}

const generateRandomString = (length) => {
    return new Promise(function (resolve, reject) {
        crypto.randomBytes((length * 3.0) / 4.0, function (err, buf) {
            if (!err) {
                var salt = buf.toString("base64")
                resolve(salt)
            } else {
                console.log("error occurred in generateRandomString: " + err)
                reject(err)
            }
        })
    })
}

const getStringByParams = (params) => {
    var data = {}
    Object.keys(params).sort().forEach(function (key, value) {
        data[key] = (params[key] !== null && params[key].toLowerCase() !== "null") ? params[key] : ""
    })
    return Object.values(data).join('|')
}

const calculateHash = (params, salt) => {
    var finalString = params + "|" + salt
    return crypto.createHash('sha256').update(finalString).digest('hex') + salt
}

const calculateChecksum = (params, key, salt) => {
    var hashString = calculateHash(params, salt)
    return encrypt(hashString, key)
}


export default function handler(request, response) {
    if (request.method === 'POST' && request.headers['content-type'] === "application/json") {
        let body = ''

        // very important to handle errors
        request.on('error', (err) => {
            if (err) {
                response.writeHead(500, {
                    'Content-Type': 'text/html'
                })
                response.write('An error occurred')
                response.end()
            }
        })

        // read chunks of POST data
        request.on('data', chunk => {
            body += chunk.toString()
        })

        // when complete POST data is received
        request.on('end', () => {

            try {

                const {
                    decrypt,
                    key,
                    params,
                    checksum
                } = JSON.parse(body)

                if (decrypt && params && key && checksum) {
                    response.writeHead(200)
                    response.write(JSON.stringify({
                        verified: verifySignature(params, key, checksum)
                    }))
                    response.end()
                } else if (!decrypt && params && key) {
                    generateSignature(params, key).then(res => {
                        response.writeHead(200)
                        response.write(JSON.stringify({
                            checksum: res
                        }))
                        response.end()
                    })
                } else {
                    response.writeHead(400)
                    response.end()
                }
            } catch (error) {
                console.error(error)
                response.writeHead(400)
                response.end()
            }
        })

    } else {
        response.writeHead(405)
        response.end()
    }
}
