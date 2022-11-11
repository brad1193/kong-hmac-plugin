"use strict"

const crypto =  require('crypto');

// This is a kong plugin that will validate HMAC signautures 

class KongPlugin {

  constructor(config) {
    this.config = config
  }

  b64ToArrBuff(b64) {
    const byteString = atob(b64);
    let byteArray = new Uint8Array(byteString.length);

    for(let i=0; i < byteString.length; i++)
        byteArray[i] = byteString.charCodeAt(i);

    return byteArray;
  }

  async access(kong) {
    kong.log.debug("Config: " + JSON.stringify(this.config));
    kong.log.debug("Secret: " + this.config.secret);
    const signatureStr = await kong.request.getHeader("signature")
    if (!signatureStr) {
      kong.log.debug("Signature Header Not Present")
      kong.response.exit(401)
    }
    const request_payload = kong.request.getRawBody() 
    const secretKey = this.b64ToArrBuff(this.config.secret)
    let encoder = new TextEncoder()
    const secret = encoder.encode(secretKey)
    if (typeof(secret) !== 'undefined') {
      const key = crypto.subtle.importKey(
        'raw',
        secret,
        { name: 'HMAC', hash: 'SHA-1' },
        false,
        ['verify']
      )
    }
    const verified = crypto.subtle.verify(
        "HMAC",
        key,
        signature,
        encoder.encode(request_payload)
    )
    if (!verified) {
        kong.log.debug("Signature: " + signatureStr + " not verifed")
        kong.response.exit(401,'Verification failed')
    }
    await Promise.all([  kong.response.exit(204, 'Successful'), ])
  }
}

module.exports = {
  Plugin: KongPlugin,
  Schema: [
    { secret: { type: "string" } },
  ],
  Version: '0.1.0',
  Priority: 0,
}
