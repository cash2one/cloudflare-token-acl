var crypto = require('crypto');

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

/**
 * Fetch and log a given request object
 * @param {Request} request
 */
async function handleRequest(request) {
  if (!request.headers.has('Cookie')) {
    return new Response('Missing Cookie value', { status: 403 })
  }

  const cookie = request.headers.get('cookie')
  if (!cookie.includes(`CloudFront-Key-Pair-Id`)) {
    //return Response.redirect('https://new.qq.com/omn/20190919/20190919A0AEOQ00.html', 302)
    return new Response('Missing CloudFront-Key-Pair-Id cookie value', { status: 403 })
  }

  if (!cookie.includes(`CloudFront-Policy`)) {
    return new Response('Missing CloudFront-Policy cookie value', { status: 403 })
  }

  if (!cookie.includes(`CloudFront-Signature`)) {
    return new Response('Missing CloudFront-Signature cookie value', { status: 403 })
  }

  const cookier = getCookies(request)
  const policy = cookier['CloudFront-Policy']
  const signature = cookier['CloudFront-Signature']
  
  const policy_data = deNormalizeBase64(policy)
  var policy_str = atob(policy_data);
  const sign_data = deNormalizeBase64(signature)
  if (!verify(policy_str,sign_data)) {
    return new Response('Signature invalid', { status: 403 })
  }

  // 验证过期时间.
  var policy_obj = JSON.parse(policy_str)
  var less_epoch_time = policy_obj['Statement'][0]['Condition']['DateLessThan']['AWS:EpochTime']
  var now_time = Math.floor(new Date() / 1000)
  if (less_epoch_time && less_epoch_time < now_time) {
    return new Response('The DateLessThan EpochTime expired', { status: 403 })
  }

  var greater_epoch_time = policy_obj['Statement'][0]['Condition']['DateGreaterThan']['AWS:EpochTime']
  if (greater_epoch_time && greater_epoch_time > now_time) {
    return new Response('The DateLessThan EpochTime expired', { status: 403 })
  }

  // 验证IP.
  var ip_address = policy_obj['Statement'][0]['Condition']['IpAddress']['AWS:SourceIp']
  if (ip_address && !validateIpAddress(ip_address)) {
    return new Response('SourceIp invalid', { status: 403 })
  }

  console.log('Got request', request)
  const response = await fetch(request)
  console.log('Got response', response)
  return response
}

/**
 * 验证签名
 * @param src_sign 签名源串
 * @param signature 已生成的签名
 * @param public_key 公钥
 * @returns {*}
 */
var verify = function(src_sign, signature) {
  const public_key = 
  '-----BEGIN PUBLIC KEY-----\n' +
  'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8sc4clRh3kcFi/Zpm+Qs6RKZF\n' +
  'mPzDcmpDjQX/x6KQ/8YkYQk9+9FVaAwsj0qWItCTt+L/4h6rC7V73/i0m89eZjnI\n' +
  '2S8Hs/2ahieDxLt3zYYfMZ5/a5pCxE1Q648aVrzv7vxTEOpbApZi41j6GKp1418Y\n' +
  'j7NoI2yPRxoK2b8XjwIDAQAB\n' +
  '-----END PUBLIC KEY-----'
    var verifier = crypto.createVerify('RSA-SHA1');
    verifier.update(src_sign);
    return verifier.verify(public_key, signature, 'base64');
}

var deNormalizeBase64 = function(str) {
  return str
    .replace(/-/g, '+')
    .replace(/_/g, '=')
    .replace(/~/g, '/');
}

var getCookies = function(request) {
  var cookies = {};
  request.headers && request.headers.get('cookie').split(';').forEach(function(cookie) {
    var parts = cookie.match(/(.*?)=(.*)$/)
    cookies[ parts[1].trim() ] = (parts[2] || '').trim();
  });
  return cookies;
}

var validateIpAddress = function(ip) {
  var without_mask_regex = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  if (ip.match(without_mask_regex)){
      return true
  }
  
  var withmask_regex = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\/)(3[0-2]|2[0-9]|1[0-9]|[1-9])$/;
  if (ip.match(withmask_regex)) {
    return true
  }
  return false
}


