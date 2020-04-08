'use strict';

const request = require('request');
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
  let maxRequestQueueLimitHit = false;
  Logger.trace({ entities }, 'doLookup');

  entities.forEach((entity) => {
    if (!entity.isPrivateIP && !IGNORED_IPS.has(entity.value)) {
      let requestOptions = {
        uri: 'https://api.shodan.io/shodan/host/' + entity.value + '?key=' + options.apiKey,
        method: 'GET',
        json: true
      };

      limiter.submit(requestEntity, entity, requestOptions, (err, result) => {
        if (maxRequestQueueLimitHit) return;
        requestResults.push([err, result]);
        if (_.isEmpty(err) && _.isEmpty(result)) {
          maxRequestQueueLimitHit = true;
          return cb({
            err: {
              message:
                `Entities: ${entities.map(({ value }) => value).join(', ')} ` +
                'were not able to be searched.'
            },
            detail: 'Hit API request Limit. Try again Later'
          });
        }

        if (requestResults.length === entities.length) {
          const [errs, results] = transpose2DArray(requestResults);
          const errors = errs.filter((err) => !_.isEmpty(err));

          if (errors.length) {
            Logger.trace({ errors }, 'Something went wrong');
            return cb({
              err: errors[0],
              detail: errors[0].detail || 'Error: Something with the Request Failed'
            });
          }

          const lookupResults = results.map(({ entity, body }) => ({
            entity,
            data: body && {
              summary: [],
              details: body
            }
          }));

          cb(null, lookupResults);
        }
      });
    }
  });
}

const requestEntity = (entity, requestOptions, callback) =>
  requestWithDefaults(requestOptions, (err, res, body) => {
    if (err || typeof res === 'undefined') {
      Logger.error({ err }, 'HTTP Request Failed');
      return callback({
        detail: 'HTTP Request Failed',
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
    } else if (res.statusCode === 503) {
      // reached request limit
      return callback({
        detail: 'Request Limit Reached'
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

module.exports = {
  doLookup,
  startup,
  validateOptions
};
