'use strict';

// This is a kong plugin that will validate HMAC signautures 

class CallrailHmacVerify {

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
    kong.request.getHeader(signature)
      .then((signatureStr) => {
      const signature = this.b64ToArrBuff(signatureStr)
      const content = kong.request.text()
      const request_payload = content
      let encoder = new TextEncoder()
      const key = crypto.subtle.importKey(
          'raw',
          encoder.encode(this.config.secret),
          { name: 'HMAC', hash: 'SHA1' },
          false,
          ['verify']
      )
      const verified = crypto.subtle.verify(
          "HMAC",
          key,
          signature,
          encoder.encode(request_payload)
      )
      if (!verified) {
          return new Response('Verification failed', {
              status: 401,
              headers: {
                  'Cache-Control': 'no-cache'
              }
          })
      }
      return new Responce('Successful', {
        status: 204,
      })
    })
  }
}
module.exports = {
  Plugin: CallrailHmacVerify,
  Schema: [
    { secret: { type: "string" } },
  ],
  Version: '0.1.0',
  Priority: 1000,
}
