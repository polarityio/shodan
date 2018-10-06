'use strict';

const request = require('request');
const config = require('./config/config');
const async = require('async');
const fs = require('fs');

let Logger;
let requestWithDefaults;

const MAX_PARALLEL_LOOKUPS = 10;

const IGNORED_IPS = new Set(['127.0.0.1', '255.255.255.255', '0.0.0.0']);

/**
 *
 * @param entities
 * @param options
 * @param cb
 */
function doLookup(entities, options, cb) {
  let lookupResults = [];
  let tasks = [];

  Logger.trace({ entities: entities }, 'doLookup');

  entities.forEach((entity) => {
    if (!entity.isPrivateIP && !IGNORED_IPS.has(entity.value)) {
      //do the lookup
      let requestOptions = {
        uri: 'https://api.shodan.io/shodan/host/' + entity.value + '?key=' + options.apiKey,
        method: 'GET',
        json: true
      };

      tasks.push(function(done) {
        requestWithDefaults(requestOptions, function(error, res, body) {
          if (error || typeof res === 'undefined') {
            Logger.error({ err: error }, 'HTTP Request Failed');
            done({
              detail: 'HTTP Request Failed',
              err: error
            });
            return;
          }

          Logger.trace({ body: body }, 'Result of Lookup');

          if (res.statusCode === 200) {
            // we got data!
            return done(null, {
              entity: entity,
              body: body
            });
          } else if (res.statusCode === 404) {
            // no result found
            return done(null, {
              entity: entity,
              body: null
            });
          } else if (res.statusCode === 503) {
            // reached request limit
            return done({
              detail: 'Request Limit Reached'
            });
          } else {
            return done({
              detail: 'Unexpected HTTP Status Received',
              httpStatus: res.statusCode,
              body: body
            });
          }
        });
      });
    }
  });

  async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, (err, results) => {
    if (err) {
      cb(err);
      return;
    }

    results.forEach((result) => {
      if (result.body === null) {
        lookupResults.push({
          entity: result.entity,
          data: null
        });
      } else {
        lookupResults.push({
          entity: result.entity,
          data: {
            summary: [],
            details: result.body
          }
        });
      }
    });

    cb(null, lookupResults);
  });
}

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
  doLookup: doLookup,
  startup: startup,
  validateOptions: validateOptions
};
