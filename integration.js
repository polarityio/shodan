'use strict';

const request = require('postman-request');
const fs = require('fs');
const Bottleneck = require('bottleneck');
const _ = require('lodash');
const cache = require('memory-cache');

const config = require('./config/config');

let bottlneckApiKeyCache = new cache.Cache();

let Logger;
let requestWithDefaults;

const IGNORED_IPS = new Set(['127.0.0.1', '255.255.255.255', '0.0.0.0']);

function doLookup(entities, options, cb) {
  let limiter = bottlneckApiKeyCache.get(options.apiKey);

  if (!limiter) {
    limiter = new Bottleneck({
      id: options.apiKey,
      maxConcurrent: 1,
      highWater: 15,
      strategy: Bottleneck.strategy.OVERFLOW,
      minTime: 1050
    });
    bottlneckApiKeyCache.put(options.apiKey, limiter);
  }

  let requestResults = [];
  Logger.trace({ entities }, 'doLookup');

  const validEntities = entities.filter(
    (entity) => !entity.isPrivateIP && !IGNORED_IPS.has(entity.value)
  );

  let requestOptions;
  validEntities.forEach((entity) => {
    if (entity.type === 'IPv4CIDR') {
      requestOptions = {
        uri:
          'https://api.shodan.io/shodan/host/search?key=' +
          options.apiKey +
          '&query=net:' +
          entity.value +
          ';has_vuln=true;',
        method: 'GET',
        json: true,
        maxResponseSize: 10000000 // 10MB in bytes
      };
    } else {
      requestOptions = {
        uri: 'https://api.shodan.io/shodan/host/' + entity.value + '?key=' + options.apiKey,
        method: 'GET',
        json: true,
        maxResponseSize: 2000000 // 2MB in bytes
      };
    }

    Logger.trace({ requestOptions }, 'Request Options');

    limiter.submit(requestEntity, entity, requestOptions, (err, result) => {
      const maxRequestQueueLimitHit =
        (_.isEmpty(err) && _.isEmpty(result)) ||
        (err && err.message === 'This job has been dropped by Bottleneck');

      if (entity.type === 'IPv4CIDR' && result && result.body) {
        // Assemble the results into a single object
        result = assembleCIDRResults(result);
      }

      requestResults.push([
        err,
        maxRequestQueueLimitHit ? { ...result, entity, limitReached: true } : result
      ]);

      if (requestResults.length === validEntities.length) {
        const [errs, results] = transpose2DArray(requestResults);
        const errors = errs.filter((err) => !_.isEmpty(err));

        if (errors.length) {
          Logger.trace({ errors }, 'Something went wrong');
          return cb({
            err: errors[0],
            detail: errors[0].detail || 'Error: Something with the Request Failed'
          });
        }

        // filter out empty results
        const filteredResults = results.filter((result) => !_.isEmpty(result));

        const lookupResults = filteredResults.map((result) => {
          if (result.limitReached) {
            return {
              entity: result.entity,
              isVolatile: true,
              data: {
                summary: ['Search Limit Reached'],
                details: { limitReached: result.limitReached, tags: ['Search Limit Reached'] }
              }
            };
          } else {
            return {
              entity: result.entity,
              data: result.body && {
                summary: createSummary(result),
                details: result.body
              }
            };
          }
        });

        Logger.trace({ lookupResults }, 'Lookup Results');
        cb(null, lookupResults);
      }
    });
  });
}

const parseErrorToReadableJSON = (error) =>
  JSON.parse(JSON.stringify(error, Object.getOwnPropertyNames(error)));

const requestEntity = (entity, requestOptions, callback) =>
  requestWithDefaults(requestOptions, (err, res, body) => {
    if (err || typeof res === 'undefined') {
      err = parseErrorToReadableJSON(err);
      Logger.error({ err }, 'HTTP Request Failed');
      let detail = 'HTTP Request Failed';
      // For some entities Shodan will return a massive response object which we should not try to handle
      // We set the maximum using the `maxResponseSize` request option and then check for this very specific
      // error message to display an error to the user.
      // See: https://github.com/postmanlabs/postman-request/pull/41/files
      if (err.message === 'Maximum response size reached') {
        detail = `Shodan response payload is too large (> 2MB) for ${entity.value}.  Results cannot be displayed`;
      }
      return callback({
        detail,
        err
      });
    }

    Logger.trace({ body }, 'Result of Lookup');

    if (res.statusCode === 200) {
      // we got data!
      return callback(null, {
        entity,
        body
      });
    } else if (res.statusCode === 404) {
      // no result found
      return callback(null, {
        entity,
        body: null
      });
    } else if (res.statusCode === 401) {
      // no result found
      return callback({
        detail: 'Unauthorized: The provided API key is invalid.'
      });
    } else if (res.statusCode === 503) {
      // reached request limit
      return callback({
        detail: 'Search Limit Reached'
      });
    } else {
      return callback({
        detail: 'Unexpected HTTP Status Received',
        httpStatus: res.statusCode,
        body
      });
    }
  });

const transpose2DArray = (results) =>
  // [[a,b],[a,b],[a,b]] -> [[a,a,a],[b,b,b]]
  results.reduce(
    (agg, [err, result]) => [
      [...agg[0], err],
      [...agg[1], result]
    ],
    [[], []]
  );

const retryEntity = ({ data: { entity } }, options, callback) =>
  doLookup([entity], options, (err, lookupResults) => {
    if (err) return callback(err);

    const lookupResult = lookupResults[0];

    if (lookupResult && lookupResult.data && lookupResult.data.details) {
      if (lookupResult.data.details.limitReached) {
        callback({ title: 'Search Limit Reached', message: 'Search Limit Still in Effect' });
      } else {
        Logger.trace({ lookupResult }, 'Retry Result');

        callback(null, lookupResult.data);
      }
    } else {
      callback(null, { noResultsFound: true, tags: ['No Results Found'] });
    }
  });

function startup(logger) {
  Logger = logger;
  let defaults = {};

  if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
    defaults.cert = fs.readFileSync(config.request.cert);
  }

  if (typeof config.request.key === 'string' && config.request.key.length > 0) {
    defaults.key = fs.readFileSync(config.request.key);
  }

  if (typeof config.request.passphrase === 'string' && config.request.passphrase.length > 0) {
    defaults.passphrase = config.request.passphrase;
  }

  if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
    defaults.ca = fs.readFileSync(config.request.ca);
  }

  if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
    defaults.proxy = config.request.proxy;
  }

  if (typeof config.request.rejectUnauthorized === 'boolean') {
    defaults.rejectUnauthorized = config.request.rejectUnauthorized;
  }

  requestWithDefaults = request.defaults(defaults);
}

function validateOptions(userOptions, cb) {
  let errors = [];
  if (
    typeof userOptions.apiKey.value !== 'string' ||
    (typeof userOptions.apiKey.value === 'string' && userOptions.apiKey.value.length === 0)
  ) {
    errors.push({
      key: 'apiKey',
      message: 'You must provide a Shodan API key'
    });
  }

  cb(null, errors);
}

// IP Address
// "body": {
//   "city": "Mountain View",
//   "region_code": "CA",
//   "os": null,
//   "tags": [],
//   "ip": 134744072,
//   "isp": "Google LLC",
//   "area_code": null,
//   "longitude": -122.0775,
//   "last_update": "2023-08-16T06:46:24.287321",
//   "ports": [
//     443,
//     53
//   ],
//   "latitude": 37.4056,
//   "hostnames": [
//     "dns.google"
//   ],
//   "country_code": "US",
//   "country_name": "United States",
//   "domains": [
//     "dns.google"
//   ],
//   "org": "Google LLC",
//   "data": []
//   "asn": "AS15169",
//   "ip_str": "8.8.8.8"
// }

// CIDR
// "asn": "AS15169",
// "hash": -553166942,
// "os": null,
// "timestamp": "2023-08-16T11:31:31.168989",
// "isp": "Google LLC",
// "transport": "tcp",
// "_shodan": {
//   "region": "na",
//   "module": "dns-tcp",
//   "ptr": true,
//   "options": {},
//   "id": "c6f00228-76f5-488e-bec5-3cc268cde897",
//   "crawler": "eb6a3b0c4c23bbec821e9a56c850ef9b7c5c7f4c"
// },
// "hostnames": [
//   "dns.google"
// ],
// "location": {
//   "city": "Mountain View",
//   "region_code": "CA",
//   "area_code": null,
//   "longitude": -122.0775,
//   "latitude": 37.4056,
//   "country_code": "US",
//   "country_name": "United States"
// },
// "dns": {
//   "software": null,
//   "recursive": true,
//   "resolver_id": null,
//   "resolver_hostname": null
// },
// "ip": 134744072,
// "domains": [
//   "dns.google"
// ],
// "org": "Google LLC",
// "data": "\nRecursion: enabled",
// "port": 53,
// "ip_str": "8.8.8.8"
// }

const assembleCIDRResults = (apiResponse) => {
  // Create resultsBody from the first match
  let resultsBody = {
    ...apiResponse.body.matches[0].location,
    data: [transformMatchToDataEntity(apiResponse.body.matches[0])],
    ports: [apiResponse.body.matches[0].port]
  };
  delete resultsBody.port; // Removing 'port' since we will be using 'ports'

  // Add matches to the resulting body
  apiResponse.body.matches.slice(1).forEach((match) => {
    // Add data to the data array
    resultsBody['data'] = resultsBody['data'].concat([transformMatchToDataEntity(match)]);

    Object.keys(match).forEach((key) => {
      if (key === 'port') {
        // Add port to the ports array
        if (!resultsBody['ports'].includes(match[key])) {
          resultsBody['ports'] = resultsBody['ports'].concat([match[key]]);
        }
      } else if (Array.isArray(match[key])) {
        // Concatenate array properties
        resultsBody[key] = (resultsBody[key] || []).concat(match[key]);
      }
    });
  });

  return { entity: apiResponse.entity, body: resultsBody };
};

// "data": [
//   {
//     "hash": -553166942,
//     "opts": {},
//     "timestamp": "2023-08-16T00:28:22.486142",
//     "isp": "Google LLC",
//     "data": "\nRecursion: enabled",
//     "_shodan": {
//       "id": "5a0be88c-f178-4c9e-b986-3746f06feba6",
//       "region": "na",
//       "options": {
//         "scan": "3RQJ8l9qNhQoORBl"
//       },
//       "module": "dns-tcp",
//       "crawler": "c4a1c68a139ae1a35b7fac13d0f8d67ac84192ff"
//     },
//     "port": 53,
//     "hostnames": [
//       "dns.google"
//     ],
//     "location": {
//       "city": "Mountain View",
//       "region_code": "CA",
//       "area_code": null,
//       "longitude": -122.0775,
//       "country_name": "United States",
//       "country_code": "US",
//       "latitude": 37.4056
//     },
//     "dns": {
//       "resolver_hostname": null,
//       "recursive": true,
//       "resolver_id": null,
//       "software": null
//     },
//     "ip": 134744072,
//     "domains": [
//       "dns.google"
//     ],
//     "org": "Google LLC",
//     "os": null,
//     "asn": "AS15169",
//     "transport": "tcp",
//     "ip_str": "8.8.8.8"
//   },
//   {
//     "hash": -553166942,
//     "opts": {
//       "raw": "34ef81820001000000000000026964067365727665720000100003"
//     },
//     "timestamp": "2023-08-16T06:46:24.287321",
//     "isp": "Google LLC",
//     "data": "\nRecursion: enabled",
//     "_shodan": {
//       "id": "c6221a80-e16e-439d-9192-02e2caefdd1f",
//       "region": "na",
//       "options": {},
//       "module": "dns-udp",
//       "crawler": "cca83004a1b8c6c55b7d66cf3c38108b16492dbe"
//     },
//     "port": 53,
//     "hostnames": [
//       "dns.google"
//     ],
//     "location": {
//       "city": "Mountain View",
//       "region_code": "CA",
//       "area_code": null,
//       "longitude": -122.0775,
//       "country_name": "United States",
//       "country_code": "US",
//       "latitude": 37.4056
//     },
//     "dns": {
//       "resolver_hostname": null,
//       "recursive": true,
//       "resolver_id": null,
//       "software": null
//     },
//     "ip": 134744072,
//     "domains": [
//       "dns.google"
//     ],
//     "org": "Google LLC",
//     "os": null,
//     "asn": "AS15169",
//     "transport": "udp",
//     "ip_str": "8.8.8.8"
//   },
//   {
//     "http": {
//       "status": 200,
//       "robots_hash": null,
//       "redirects": [
//         {
//           "host": "8.8.8.8",
//           "data": "HTTP/1.1 302 Found\r\nX-Content-Type-Options: nosniff\r\nAccess-Control-Allow-Origin: *\r\nLocation: https://dns.google/\r\nDate: Wed, 16 Aug 2023 05:47:53 GMT\r\nContent-Type: text/html; charset=UTF-8\r\nServer: HTTP server (unknown)\r\nContent-Length: 216\r\nX-XSS-Protection: 0\r\nX-Frame-Options: SAMEORIGIN\r\nAlt-Svc: h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000\r\n\r\n",
//           "location": "/"
//         }
//       ],
//       "securitytxt": null,
//       "title": "Google Public DNS",
//       "sitemap_hash": null,
//       "html_hash": -46589965,
//       "robots": null,
//       "favicon": {
//         "hash": 56641965,
//         "data": "iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAMAAAD04JH5AAABa1BMVEUAAAA0p100qFM0qFY1pW81\npmg1p141p2M2pHw2pH02pXU3oYs3ook4n5k4oY85np86m6s6m6w7mLo7mLs7mbY7mbc7p1M8lcQ8\nlsM+ks4+ks8+oYo/j9g/j9k/kNg/p1NAiudAi+VAjOFAjeBBh+9BiO1BietChfRChvJEhfRIhvNI\npVJJonNKhPJMhPJMpVJRkcdTh/BXo1FZie5ag+xeie1fhORmlZ5on1Bsnk90juV4m05+jOCAmE2D\ngMuMkdmNk0yQkkuQlNeWltSXj0qliEiubLqvgka0f0W1lbm4m7e7mrS9eUPBdkLHcEDOm5vSZj3S\noJXTZD3UoJLZXTvdWTrgonzhUzjkTjflp3LmSjfoRjboRzbqQzXqRDXqRTXqRjXqRzXsYDHtYjHt\nYzHtqlruqlfveSzveizweyzwr0/yjSbyjib1nSD1nh/1nx/3tSz4rBf4rRb4tyb6uQn6uQr6uhn7\nugj7vAU/At79AAAAAXRSTlMAQObYZgAAArlJREFUeNrt2PVz1EAYxvFlcSnFXQoUXgoUdyvu7ra4\nFy22fz53NJ27Xmx38z7vwpHnl860yXw/c9PJJVGqXuXp9KLGBRG6bHHrWIJ2XeQ8iKB1VIH2Xuw+\nryCkr7dH7vcSRe3PWE9cgqD+xJVETIKgvp5PxCQI68/eyAUI60/uI+IRhPX1MmICBPbnEjEJnC52\nqd9O7+cCuF9p2/8wZS3hAUXHLiZiEnh+zSR/7CE4oPD4SRvYAP7fss1L8AoCA0pOWUjEJQi5y9DL\nB+MC1F4CA8pOIj5A4G1elwNUDfjfAaoGhAGUJAB8Ja4BQX3JL0PO/l8K0P59QQBv31tAJAPQYn2v\n5yIC9D2eDImkAe0EIlTf4fXEPiJkvxSwZTe2XyZIXgUC+yWCefh+oWDmoEBfHXd5FQjsK3V5Ww5g\nqUxfqdtHMvtzhPJKmYfnVqf70/qF+qa5Gwc6+xPWyfRNsgenOwBLZP4BTGtXdrb3ewYkLgFm3O4e\na/XTrwIRAtOxx5c2j12CVxHhBSa9W4dGAQuI8AKTtUdnFzX6s7YSXmBydm2/nrqG8ACTu3unjhLB\nBaZoRHBBYd+caT/08CYAoDCfPvz1navnh3ZwCnzqf2Yb+/Kq6djFAfDNJ4LRfXt//+bFE3uqCAL6\n4whjjusXTh4cYASUnWaz9lOunyOwcn0swOlUIEDJASp8ANkCwQ+gOwCV+pmCbgCoGiAIqNiPDrA1\nIDLAdinACPb/bQDPHRnz/ZgggKkffEdmsQAj1g8EWD6ACngutJx9/ydTa4UA2QTL3S9+O+JThwBa\nisbPr5i+gyDZR1DfGTAM6jsL3sQGPEf1XQVPfqD6roIRWN9R8AnXdxMM4/JugrfIvovgBbTvIHj6\nHZl3EYxg++WEz+B8KeEDPF8ieIfPFxteStSLDM9+ydTzEapelf0GmFdLbOXMqToAAAAASUVORK5C\nYII=\n",
//         "location": "https://dns.google:443/static/93dd5954/favicon.png"
//       },
//       "headers_hash": 818523308,
//       "host": "dns.google",
//       "html": "<!DOCTYPE html>\n<html lang=\"en\"> <head> <title>Google Public DNS</title>  <meta charset=\"UTF-8\"> <link href=\"/static/93dd5954/favicon.png\" rel=\"shortcut icon\" type=\"image/png\"> <link href=\"/static/836aebc6/matter.min.css\" rel=\"stylesheet\"> <link href=\"/static/b8536c37/shared.css\" rel=\"stylesheet\"> <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">  <link href=\"/static/d05cd6ba/root.css\" rel=\"stylesheet\"> </head> <body> <span class=\"filler top\"></span>   <div class=\"logo\" title=\"Google Public DNS\"> <div class=\"logo-text\"><span>Public DNS</span></div> </div>  <form action=\"/query\" method=\"GET\">  <div class=\"row\"> <label class=\"matter-textfield-outlined\"> <input type=\"text\" name=\"name\" placeholder=\"&nbsp;\"> <span>DNS Name</span> <p class=\"help\"> Enter a domain (like example.com) or IP address (like 8.8.8.8 or 2001:4860:4860::8844) here. </p> </label> <button class=\"matter-button-contained matter-primary\" type=\"submit\">Resolve</button> </div> </form>  <span class=\"filler bottom\"></span> <footer class=\"row\"> <a href=\"https://developers.google.com/speed/public-dns\">Help</a> <a href=\"/cache\">Cache Flush</a> <span class=\"filler\"></span> <a href=\"https://developers.google.com/speed/public-dns/docs/using\"> Get Started with Google Public DNS </a> </footer>   <script nonce=\"mncrQ4k6QWkhLYdSddWGiw\">document.forms[0].name.focus();</script> </body> </html>",
//       "location": "/",
//       "components": {},
//       "server": "scaffolding on HTTPServer2",
//       "sitemap": null,
//       "securitytxt_hash": null
//     },
//     "opts": {
//       "vulns": [],
//       "heartbleed": "2023/08/16 05:47:57 8.8.8.8:443 - SAFE\n"
//     },
//     "timestamp": "2023-08-16T05:47:53.468363",
//     "org": "Google LLC",
//     "isp": "Google LLC",
//     "data": "HTTP/1.1 200 OK\r\nContent-Security-Policy: object-src 'none';base-uri 'self';script-src 'nonce-mncrQ4k6QWkhLYdSddWGiw' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/honest_dns/1_0;frame-ancestors 'none'\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nX-Content-Type-Options: nosniff\r\nContent-Type: text/html; charset=UTF-8\r\nDate: Wed, 16 Aug 2023 05:47:53 GMT\r\nServer: scaffolding on HTTPServer2\r\nCache-Control: private\r\nX-XSS-Protection: 0\r\nX-Frame-Options: SAMEORIGIN\r\nAlt-Svc: h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000\r\nAccept-Ranges: none\r\nVary: Accept-Encoding\r\nTransfer-Encoding: chunked\r\n\r\n",
//     "_shodan": {
//       "id": "3f95bccc-d910-4bf8-936a-f4421d91ca2c",
//       "region": "na",
//       "options": {
//         "scan": "0X4WFpfoqLNE7PUV"
//       },
//       "module": "https",
//       "crawler": "cca83004a1b8c6c55b7d66cf3c38108b16492dbe"
//     },
//     "port": 443,
//     "ssl": {
//       "chain_sha256": [
//         "33aa2d1350f58cb3e987cbdd8f353fd4882f2263258db337866f87f3d3f5446c",
//         "23ecb03eec17338c4e33a6b48a41dc3cda12281bbc3ff813c0589d6cc2387522",
//         "3ee0278df71fa3c125c4cd487f01d774694e6fc57e0cd94c24efd769133918e5"
//       ],
//       "jarm": "29d3fd00029d29d00042d43d00041d598ac0c1012db967bb1ad0ff2491b3ae",
//       "chain": [
//         "-----BEGIN CERTIFICATE-----\nMIIF4zCCBMugAwIBAgIRAL8k191GosmLCe0SKUm2E1gwDQYJKoZIhvcNAQELBQAw\nRjELMAkGA1UEBhMCVVMxIjAgBgNVBAoTGUdvb2dsZSBUcnVzdCBTZXJ2aWNlcyBM\nTEMxEzARBgNVBAMTCkdUUyBDQSAxQzMwHhcNMjMwNzE3MDgyMjA5WhcNMjMxMDA5\nMDgyMjA4WjAVMRMwEQYDVQQDEwpkbnMuZ29vZ2xlMIIBIjANBgkqhkiG9w0BAQEF\nAAOCAQ8AMIIBCgKCAQEAsmgK5I0v+WKYzHcLoJgrLLWKPNP5uHXGZd1uwzttBvpI\nqJPLtnEtcplyAZVQTOFyzaIEHY07oT6TAS5GY47Z4Cu96jtl3lse5uyaWWMgwZO0\nDupfHEFEhlHHXAntbT2RHzyGof7T3vDzXOYzk4As0nnovya8nXbUzGGOSdo2uCkS\nizoqeW0ScsWOkmhAWVpOhp7HuRq7BpYCj+wVPfvK1OxaGHGuMnofMw+FgRZoVh67\nCmynhJ22BJpm9xpEQIu0S7z1rE00zJ13kHbriK2BmXZ0vr708KFqZeEAmj88y4AN\n4a9Wtq1GMfgYWs7nAPKMkr23FVeNPb3jKEhDl5AuOwIDAQABo4IC+zCCAvcwDgYD\nVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAw\nHQYDVR0OBBYEFK49aoDRsz/gnSGYAelD+l3PVWFwMB8GA1UdIwQYMBaAFIp0f6+F\nze6VzT2c0OJGFPNxNR0nMGoGCCsGAQUFBwEBBF4wXDAnBggrBgEFBQcwAYYbaHR0\ncDovL29jc3AucGtpLmdvb2cvZ3RzMWMzMDEGCCsGAQUFBzAChiVodHRwOi8vcGtp\nLmdvb2cvcmVwby9jZXJ0cy9ndHMxYzMuZGVyMIGsBgNVHREEgaQwgaGCCmRucy5n\nb29nbGWCDmRucy5nb29nbGUuY29tghAqLmRucy5nb29nbGUuY29tggs4ODg4Lmdv\nb2dsZYIQZG5zNjQuZG5zLmdvb2dsZYcECAgICIcECAgEBIcQIAFIYEhgAAAAAAAA\nAACIiIcQIAFIYEhgAAAAAAAAAACIRIcQIAFIYEhgAAAAAAAAAABkZIcQIAFIYEhg\nAAAAAAAAAAAAZDAhBgNVHSAEGjAYMAgGBmeBDAECATAMBgorBgEEAdZ5AgUDMDwG\nA1UdHwQ1MDMwMaAvoC2GK2h0dHA6Ly9jcmxzLnBraS5nb29nL2d0czFjMy9mVkp4\nYlYtS3Rtay5jcmwwggEEBgorBgEEAdZ5AgQCBIH1BIHyAPAAdgC3Pvsk35xNunXy\nOcW6WPRsXfxCz3qfNcSeHQmBJe20mQAAAYljKEdTAAAEAwBHMEUCID+0IGEcqw0M\nug604MZfDQAsTzMa9UUQUFRetd7kfEHhAiEA6mACdfgvfl9RFOB7ydC/UY4TXQqq\nOsWLnlVcbcak0XEAdgDoPtDaPvUGNTLnVyi8iWvJA9PL0RFr7Otp4Xd9bQa9bgAA\nAYljKEdCAAAEAwBHMEUCIEAJUZKmUXZypKs9RfHq+CSwETfX35+RpCrE4ZlDcv43\nAiEAlsFwD1cxK3HKLI6FQblWmioB/MSZP/6dY7MG1km22jQwDQYJKoZIhvcNAQEL\nBQADggEBAMAGOicitYr940WQ6/+kkAtPSSlC30JzlL1YL8cq0L1T/XaqOWY7JoR2\n1wBljGdkjME8/jKGumbFz4UmKdjT+5utSylzk+6LvYvNWqQghRyETRauqPiWF5Mg\nthgKuofc6JVW7hX5kLkiGjdSFSGotR6EDVLhC1twknvJOb8+1mit7vOPK5mtfDEL\nuYPa5/ty4W/6WlzxcCvxDIVLD30yGrQRRiKSX+WJMcj3yW3SwPhkXJcS+janI4e+\nol9/QMLe2Unhss3Pe37Mv4Z/Y35E1G/1RzJDmq6HF4CHzX1h5hwb3q2E75yMGqTW\nWNT67sBElfA9nuU9deZtCdd3Hv9Xie8=\n-----END CERTIFICATE-----\n",
//         "-----BEGIN CERTIFICATE-----\nMIIFljCCA36gAwIBAgINAgO8U1lrNMcY9QFQZjANBgkqhkiG9w0BAQsFADBHMQsw\nCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEU\nMBIGA1UEAxMLR1RTIFJvb3QgUjEwHhcNMjAwODEzMDAwMDQyWhcNMjcwOTMwMDAw\nMDQyWjBGMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZp\nY2VzIExMQzETMBEGA1UEAxMKR1RTIENBIDFDMzCCASIwDQYJKoZIhvcNAQEBBQAD\nggEPADCCAQoCggEBAPWI3+dijB43+DdCkH9sh9D7ZYIl/ejLa6T/belaI+KZ9hzp\nkgOZE3wJCor6QtZeViSqejOEH9Hpabu5dOxXTGZok3c3VVP+ORBNtzS7XyV3NzsX\nlOo85Z3VvMO0Q+sup0fvsEQRY9i0QYXdQTBIkxu/t/bgRQIh4JZCF8/ZK2VWNAcm\nBA2o/X3KLu/qSHw3TT8An4Pf73WELnlXXPxXbhqW//yMmqaZviXZf5YsBvcRKgKA\ngOtjGDxQSYflispfGStZloEAoPtR28p3CwvJlk/vcEnHXG0g/Zm0tOLKLnf9LdwL\ntmsTDIwZKxeWmLnwi/agJ7u2441Rj72ux5uxiZ0CAwEAAaOCAYAwggF8MA4GA1Ud\nDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwEgYDVR0T\nAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUinR/r4XN7pXNPZzQ4kYU83E1HScwHwYD\nVR0jBBgwFoAU5K8rJnEaK0gnhS9SZizv8IkTcT4waAYIKwYBBQUHAQEEXDBaMCYG\nCCsGAQUFBzABhhpodHRwOi8vb2NzcC5wa2kuZ29vZy9ndHNyMTAwBggrBgEFBQcw\nAoYkaHR0cDovL3BraS5nb29nL3JlcG8vY2VydHMvZ3RzcjEuZGVyMDQGA1UdHwQt\nMCswKaAnoCWGI2h0dHA6Ly9jcmwucGtpLmdvb2cvZ3RzcjEvZ3RzcjEuY3JsMFcG\nA1UdIARQME4wOAYKKwYBBAHWeQIFAzAqMCgGCCsGAQUFBwIBFhxodHRwczovL3Br\naS5nb29nL3JlcG9zaXRvcnkvMAgGBmeBDAECATAIBgZngQwBAgIwDQYJKoZIhvcN\nAQELBQADggIBAIl9rCBcDDy+mqhXlRu0rvqrpXJxtDaV/d9AEQNMwkYUuxQkq/BQ\ncSLbrcRuf8/xam/IgxvYzolfh2yHuKkMo5uhYpSTld9brmYZCwKWnvy15xBpPnrL\nRklfRuFBsdeYTWU0AIAaP0+fbH9JAIFTQaSSIYKCGvGjRFsqUBITTcFTNvNCCK9U\n+o53UxtkOCcXCb1YyRt8OS1b887U7ZfbFAO/CVMkH8IMBHmYJvJh8VNS/UKMG2Yr\nPxWhu//2m+OBmgEGcYk1KCTd4b3rGS3hSMs9WYNRtHTGnXzGsYZbr8w0xNPM1IER\nlQCh9BIiAfq0g3GvjLeMcySsN1PCAJA/Ef5c7TaUEDu9Ka7ixzpiO2xj2YC/WXGs\nYye5TBeg2vZzFb8q3o/zpWwygTMD0IZRcZk0upONXbVRWPeyk+gB9lm+cZv9TSjO\nz23HFtz30dZGm6fKa+l3D/2gthsjgx0QGtkJAITgRNOidSOzNIb2ILCkXhAd4FJG\nAJ2xDx8hcFH1mt0G/FX0Kw4zd8NLQsLxdxP8c4CU6x+7Nz/OAipmsHMdMqUybDKw\njuDEI/9bfU1lcKwrmz3O2+BtjjKAvpafkmO8l7tdufThcV4q5O8DIrGKZTqPwJNl\n1IXNDw9bg1kWRxYtnCQ6yICmJhSFm/Y3m6xv+cXDBlHz4n/FsRC6UfTd\n-----END CERTIFICATE-----\n",
//         "-----BEGIN CERTIFICATE-----\nMIIFYjCCBEqgAwIBAgIQd70NbNs2+RrqIQ/E8FjTDTANBgkqhkiG9w0BAQsFADBX\nMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEQMA4GA1UE\nCxMHUm9vdCBDQTEbMBkGA1UEAxMSR2xvYmFsU2lnbiBSb290IENBMB4XDTIwMDYx\nOTAwMDA0MloXDTI4MDEyODAwMDA0MlowRzELMAkGA1UEBhMCVVMxIjAgBgNVBAoT\nGUdvb2dsZSBUcnVzdCBTZXJ2aWNlcyBMTEMxFDASBgNVBAMTC0dUUyBSb290IFIx\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAthECix7joXebO9y/lD63\nladAPKH9gvl9MgaCcfb2jH/76Nu8ai6Xl6OMS/kr9rH5zoQdsfnFl97vufKj6bwS\niV6nqlKr+CMny6SxnGPb15l+8Ape62im9MZaRw1NEDPjTrETo8gYbEvs/AmQ351k\nKSUjB6G00j0uYODP0gmHu81I8E3CwnqIiru6z1kZ1q+PsAewnjHxgsHA3y6mbWwZ\nDrXYfiYaRQM9sHmklCitD38m5agI/pboPGiUU+6DOogrFZYJsuB6jC511pzrp1Zk\nj5ZPaK49l8KEj8C8QMALXL32h7M1bKwYUH+E4EzNktMg6TO8UpmvMrUpsyUqtEj5\ncuHKZPfmghCN6J3Cioj6OGaK/GP5Afl4/Xtcd/p2h/rs37EOeZVXtL0m79YB0esW\nCruOC7XFxYpVq9Os6pFLKcwZpDIlTirxZUTQAs6qzkm06p98g7BAe+dDq6dso499\niYH6TKX/1Y7DzkvgtdizjkXPdsDtQCv9Uw+wp9U7DbGKogPeMa3Md+pvez7W35Ei\nEua++tgy/BBjFFFy3l3WFpO9KWgz7zpm7AeKJt8T11dleCfeXkkUAKIAf5qoIbap\nsZWwpbkNFhHax2xIPEDgfg1azVY80ZcFuctL7TlLnMQ/0lUTbiSw1nH69MG6zO0b\n9f6BQdgAmD06yK56mDcYBZUCAwEAAaOCATgwggE0MA4GA1UdDwEB/wQEAwIBhjAP\nBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTkrysmcRorSCeFL1JmLO/wiRNxPjAf\nBgNVHSMEGDAWgBRge2YaRQ2XyolQL30EzTSo//z9SzBgBggrBgEFBQcBAQRUMFIw\nJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnBraS5nb29nL2dzcjEwKQYIKwYBBQUH\nMAKGHWh0dHA6Ly9wa2kuZ29vZy9nc3IxL2dzcjEuY3J0MDIGA1UdHwQrMCkwJ6Al\noCOGIWh0dHA6Ly9jcmwucGtpLmdvb2cvZ3NyMS9nc3IxLmNybDA7BgNVHSAENDAy\nMAgGBmeBDAECATAIBgZngQwBAgIwDQYLKwYBBAHWeQIFAwIwDQYLKwYBBAHWeQIF\nAwMwDQYJKoZIhvcNAQELBQADggEBADSkHrEoo9C0dhemMXoh6dFSPsjbdBZBiLg9\nNR3t5P+T4Vxfq7vqfM/b5A3Ri1fyJm9bvhdGaJQ3b2t6yMAYN/olUazsaL+yyEn9\nWprKASOshIArAoyZl+tJaox118fessmXn1hIVw41oeQa1v1vg4Fv74zPl6/AhSrw\n9U5pCZEt4Wi4wStz6dTZ/CLANx8LZh1J7QJVj2fhMtfTJr9w4z30Z209fOU0iOMy\n+qduBmpvvYuR7hZL6Dupszfnw0Skfths18dG9ZKb59UhvmaSGZRVbNQpsg3BZlvi\nd0lIKO2d1xozclOzgjXPYovJJIultzkMu34qQb9Sz/yilrbCgj8=\n-----END CERTIFICATE-----\n"
//       ],
//       "dhparams": null,
//       "versions": [
//         "-TLSv1",
//         "-SSLv2",
//         "-SSLv3",
//         "-TLSv1.1",
//         "TLSv1.2",
//         "TLSv1.3"
//       ],
//       "acceptable_cas": [],
//       "tlsext": [
//         {
//           "id": 51,
//           "name": "key_share"
//         },
//         {
//           "id": 43,
//           "name": "supported_versions"
//         }
//       ],
//       "ja3s": "66e33336e3e99f75410126f42d44cc81",
//       "cert": {
//         "sig_alg": "sha256WithRSAEncryption",
//         "issued": "20230717082209Z",
//         "expires": "20231009082208Z",
//         "expired": false,
//         "version": 2,
//         "extensions": [
//           {
//             "critical": true,
//             "data": "\\x03\\x02\\x05\\xa0",
//             "name": "keyUsage"
//           },
//           {
//             "data": "0\\n\\x06\\x08+\\x06\\x01\\x05\\x05\\x07\\x03\\x01",
//             "name": "extendedKeyUsage"
//           },
//           {
//             "critical": true,
//             "data": "0\\x00",
//             "name": "basicConstraints"
//           },
//           {
//             "data": "\\x04\\x14\\xae=j\\x80\\xd1\\xb3?\\xe0\\x9d!\\x98\\x01\\xe9C\\xfa]\\xcfUap",
//             "name": "subjectKeyIdentifier"
//           },
//           {
//             "data": "0\\x16\\x80\\x14\\x8at\\x7f\\xaf\\x85\\xcd\\xee\\x95\\xcd=\\x9c\\xd0\\xe2F\\x14\\xf3q5\\x1d\\'",
//             "name": "authorityKeyIdentifier"
//           },
//           {
//             "data": "0\\\\0\\'\\x06\\x08+\\x06\\x01\\x05\\x05\\x070\\x01\\x86\\x1bhttp://ocsp.pki.goog/gts1c301\\x06\\x08+\\x06\\x01\\x05\\x05\\x070\\x02\\x86%http://pki.goog/repo/certs/gts1c3.der",
//             "name": "authorityInfoAccess"
//           },
//           {
//             "data": "0\\x81\\xa1\\x82\\ndns.google\\x82\\x0edns.google.com\\x82\\x10*.dns.google.com\\x82\\x0b8888.google\\x82\\x10dns64.dns.google\\x87\\x04\\x08\\x08\\x08\\x08\\x87\\x04\\x08\\x08\\x04\\x04\\x87\\x10 \\x01H`H`\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x88\\x88\\x87\\x10 \\x01H`H`\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x88D\\x87\\x10 \\x01H`H`\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00dd\\x87\\x10 \\x01H`H`\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00d",
//             "name": "subjectAltName"
//           },
//           {
//             "data": "0\\x180\\x08\\x06\\x06g\\x81\\x0c\\x01\\x02\\x010\\x0c\\x06\\n+\\x06\\x01\\x04\\x01\\xd6y\\x02\\x05\\x03",
//             "name": "certificatePolicies"
//           },
//           {
//             "data": "0301\\xa0/\\xa0-\\x86+http://crls.pki.goog/gts1c3/fVJxbV-Ktmk.crl",
//             "name": "crlDistributionPoints"
//           },
//           {
//             "data": "\\x04\\x81\\xf2\\x00\\xf0\\x00v\\x00\\xb7>\\xfb$\\xdf\\x9cM\\xbau\\xf29\\xc5\\xbaX\\xf4l]\\xfcB\\xcfz\\x9f5\\xc4\\x9e\\x1d\\t\\x81%\\xed\\xb4\\x99\\x00\\x00\\x01\\x89c(GS\\x00\\x00\\x04\\x03\\x00G0E\\x02 ?\\xb4 a\\x1c\\xab\\r\\x0c\\xba\\x0e\\xb4\\xe0\\xc6_\\r\\x00,O3\\x1a\\xf5E\\x10PT^\\xb5\\xde\\xe4|A\\xe1\\x02!\\x00\\xea`\\x02u\\xf8/~_Q\\x14\\xe0{\\xc9\\xd0\\xbfQ\\x8e\\x13]\\n\\xaa:\\xc5\\x8b\\x9eU\\\\m\\xc6\\xa4\\xd1q\\x00v\\x00\\xe8>\\xd0\\xda>\\xf5\\x0652\\xe7W(\\xbc\\x89k\\xc9\\x03\\xd3\\xcb\\xd1\\x11k\\xec\\xebi\\xe1w}m\\x06\\xbdn\\x00\\x00\\x01\\x89c(GB\\x00\\x00\\x04\\x03\\x00G0E\\x02 @\\tQ\\x92\\xa6Qvr\\xa4\\xab=E\\xf1\\xea\\xf8$\\xb0\\x117\\xd7\\xdf\\x9f\\x91\\xa4*\\xc4\\xe1\\x99Cr\\xfe7\\x02!\\x00\\x96\\xc1p\\x0fW1+q\\xca,\\x8e\\x85A\\xb9V\\x9a*\\x01\\xfc\\xc4\\x99?\\xfe\\x9dc\\xb3\\x06\\xd6I\\xb6\\xda4",
//             "name": "ct_precert_scts"
//           }
//         ],
//         "fingerprint": {
//           "sha256": "33aa2d1350f58cb3e987cbdd8f353fd4882f2263258db337866f87f3d3f5446c",
//           "sha1": "22f7c918e727f12c436417533b8b4acd3fb33313"
//         },
//         "serial": 2.5407384813117563e+38,
//         "subject": {
//           "CN": "dns.google"
//         },
//         "pubkey": {
//           "type": "rsa",
//           "bits": 2048
//         },
//         "issuer": {
//           "C": "US",
//           "CN": "GTS CA 1C3",
//           "O": "Google Trust Services LLC"
//         }
//       },
//       "cipher": {
//         "version": "TLSv1.3",
//         "bits": 256,
//         "name": "TLS_AES_256_GCM_SHA384"
//       },
//       "trust": {
//         "revoked": false,
//         "browser": null
//       },
//       "handshake_states": [
//         "before SSL initialization",
//         "SSLv3/TLS write client hello",
//         "SSLv3/TLS read server hello",
//         "TLSv1.3 read encrypted extensions",
//         "SSLv3/TLS read server certificate",
//         "TLSv1.3 read server certificate verify",
//         "SSLv3/TLS read finished",
//         "SSLv3/TLS write change cipher spec",
//         "SSLv3/TLS write finished",
//         "SSL negotiation finished successfully"
//       ],
//       "alpn": [],
//       "ocsp": {}
//     },
//     "hostnames": [
//       "dns.google"
//     ],
//     "location": {
//       "city": "Mountain View",
//       "region_code": "CA",
//       "area_code": null,
//       "longitude": -122.0775,
//       "country_name": "United States",
//       "country_code": "US",
//       "latitude": 37.4056
//     },
//     "ip": 134744072,
//     "domains": [
//       "dns.google"
//     ],
//     "hash": 25746051,
//     "os": null,
//     "asn": "AS15169",
//     "transport": "tcp",
//     "ip_str": "8.8.8.8"
//   }
// ]
const transformMatchToDataEntity = (match) => {
  return {
    ...match
  };
};

/**
 * Creates the Summary Tags (currently just tags for ports)
 * @param apiResponse
 * @returns {string[]}
 */
const createSummary = (apiResponse) => {
  Logger.trace({ apiResponse }, 'Creating Summary Tags');

  const tags = createPortTags(apiResponse);
  Logger.trace({ tags }, 'Summary Tags Created');

  if (Array.isArray(apiResponse.body.tags)) {
    const apiTags = apiResponse.body.tags;

    apiTags.slice(0, 5).forEach((tag) => {
      tags.push(tag);
    });

    if (apiTags.length > 5) {
      tags.push(`+${apiTags.length - 5} more tags`);
    }
  }

  Logger.trace({ tags }, 'final tags');
  return tags;
};

/**
 * Create the Port Summary Tags
 *
 * Sort the ports when displaying from smallest to largest number
 *
 * If there are less than or equal to 10 ports just show the ports like we currently do (however, they will now be sorted)
 * If there are greater than 10 ports do the following:
 *   1. Sort the ports and ensure we're displaying ports under 1024 before ports over 1024.
 *   2. Display the first 10 ports less than 1024 and then text that says +X more.
 *   These are called Reserved Ports (note that reserved ports are 0 to 1023 inclusive)
 *
 * Example:
 * ```
 * Reserved Ports: 1, 2, 3, 4, 25, 80, 443, 500, 600, 601, +5 more
 * ```
 * Add a second tag that provides a count of how many ports greater than or equal to 1024 are open
 * (these are called ephemeral ports).
 *
 * Example:
 * ```
 * 679 ephemeral ports
 * ```
 * @param apiResponse
 * @returns {[string]}
 */
const createPortTags = (apiResponse) => {
  // if aipResponse is array, then we have multiple results
  Logger.trace({ apiResponse }, 'Creating Port Tags');
  const portTags = [];
  const ports = Array.from(apiResponse.body.ports || [apiResponse.body.port] || []);

  // sort the ports from smallest to largest
  ports.sort((a, b) => {
    return a - b;
  });

  if (ports.length === 0) {
    return [`No Open Ports`];
  } else if (ports.length <= 10) {
    return [`Ports: ${ports.join(', ')}`];
  } else {
    let splitIndex = ports.length;
    for (let i = 0; i < ports.length; i++) {
      if (ports[i] > 1024) {
        splitIndex = i;
        break;
      }
    }

    // ports array is for reserved ports
    // ephemeralPorts is for ephemeral ports ( ports > 1024)
    const ephemeralPorts = ports.splice(splitIndex);
    const numEphemeralPorts = ephemeralPorts.length;
    const firstTenReservedPorts = ports.slice(0, 10);
    const extraReservedCount = ports.length > 10 ? ports.length - 10 : 0;

    if (firstTenReservedPorts.length > 0) {
      portTags.push(
        `Reserved Ports: ${firstTenReservedPorts.join(', ')}${
          extraReservedCount > 0 ? ', +' + extraReservedCount + ' more' : ''
        }`
      );
    }

    if (numEphemeralPorts > 0) {
      portTags.push(`${numEphemeralPorts} ephemeral ports`);
    }

    Logger.trace({ portTags }, 'Port Tags Created');
    return portTags;
  }
};

module.exports = {
  startup,
  doLookup,
  validateOptions,
  onMessage: retryEntity
};
