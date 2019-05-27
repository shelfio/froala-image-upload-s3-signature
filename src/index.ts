/**
 * Get signature for S3.
 *
 * @params config:
 *   {
 *     bucket: 'bucketName',
 *
 *     //http://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region
 *     region: 's3',
 *     keyStart: 'editor/',
 *     // custom expiration time for the signature in ms (default 5 minutes)
 *     expiresInMS: 1000 * 5 * 60,
 *     acl: 'public-read',
 *     accessKey: 'YOUR-AMAZON-S3-PUBLIC-ACCESS-KEY',
 *     secretKey: 'YOUR-AMAZON-S3-SECRET-ACCESS-KEY'
 *   }
 *
 * @return:
 *   {
 *     bucket: bucket,
 *     region: region,
 *     keyStart: keyStart,
 *     params: {
 *       acl: acl,
 *       policy: policy,
 *       'x-amz-algorithm': 'AWS4-HMAC-SHA256',
 *       'x-amz-credential': xAmzCredential,
 *       'x-amz-date': xAmzDate,
 *       'x-amz-signature': signature
 *     }
 *   }
 */

export interface GetHashConfig {
  bucket: string;
  region?: string;
  keyStart: string;
  expiresInMS?: number;
  acl: string;
  accessKey: string;
  secretKey: string;
}

export interface GetHashResult {
  bucket: string;
  region: string;
  keyStart: string;
  params: S3SignatureParams;
}

export interface S3SignatureParams {
  acl: string;
  policy: string;
  'x-amz-algorithm': string;
  'x-amz-credential': string;
  'x-amz-date': string;
  'x-amz-signature': string;
}

export function getHash(config: GetHashConfig): GetHashResult {
  // Check default region.
  config.region = config.region || 'us-east-1';
  config.region = config.region == 's3' ? 'us-east-1' : config.region;

  const bucket = config.bucket;
  const region = config.region;
  const keyStart = config.keyStart;
  const acl = config.acl;

  // These can be found on your Account page, under Security Credentials > Access Keys.
  const accessKeyId = config.accessKey;
  const secret = config.secretKey;

  const date = new Date().toISOString();
  const dateString = date.substr(0, 4) + date.substr(5, 2) + date.substr(8, 2); // Ymd format.

  const credential = [accessKeyId, dateString, region, 's3/aws4_request'].join('/');
  const xAmzDate = dateString + 'T000000Z';

  const expiresInMS = config.expiresInMS || 5 * 60 * 1000;

  const policy = {
    expiration: new Date(new Date().getTime() + expiresInMS).toISOString(),
    conditions: [
      {bucket: bucket},
      {acl: acl},
      {success_action_status: '201'},
      {'x-requested-with': 'xhr'},
      {'x-amz-algorithm': 'AWS4-HMAC-SHA256'},
      {'x-amz-credential': credential},
      {'x-amz-date': xAmzDate},
      ['starts-with', '$key', keyStart],
      ['starts-with', '$Content-Type', ''] // accept all files
    ]
  };
  const policyBase64 = Buffer.from(JSON.stringify(policy)).toString('base64');

  function hmac(key, string) {
    const hmac = require('crypto').createHmac('sha256', key);
    hmac.end(string);

    return hmac.read();
  }

  const dateKey = hmac('AWS4' + secret, dateString);
  const dateRegionKey = hmac(dateKey, region);
  const dateRegionServiceKey = hmac(dateRegionKey, 's3');
  const signingKey = hmac(dateRegionServiceKey, 'aws4_request');
  const signature = hmac(signingKey, policyBase64).toString('hex');

  return {
    bucket: bucket,
    region: region != 'us-east-1' ? 's3-' + region : 's3',
    keyStart: keyStart,
    params: {
      acl: acl,
      policy: policyBase64,
      'x-amz-algorithm': 'AWS4-HMAC-SHA256',
      'x-amz-credential': credential,
      'x-amz-date': xAmzDate,
      'x-amz-signature': signature
    }
  };
}
