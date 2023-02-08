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

  validEntities.forEach((entity) => {
    let requestOptions = {
      uri: 'https://api.shodan.io/shodan/host/' + entity.value + '?key=' + options.apiKey,
      method: 'GET',
      json: true,
      maxResponseSize: 2000000 // 2MB in bytes
    };

    limiter.submit(requestEntity, entity, requestOptions, (err, result) => {
      const maxRequestQueueLimitHit =
        (_.isEmpty(err) && _.isEmpty(result)) ||
        (err && err.message === 'This job has been dropped by Bottleneck');

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
  Logger.trace({ apiResponse }, 'Creating Port Tags');
  const portTags = [];
  const ports = Array.from(apiResponse.body.ports);

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
    //const firstFiveEphemeralPorts = ephemeralPorts.slice(0, 5);
    const extraReservedCount = ports.length > 10 ? ports.length - 10 : 0;
    //const extraEphemeralCount = ephemeralPorts.length > 5 ? ephemeralPorts.length - 5 : 0;

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
    //
    // if (firstFiveEphemeralPorts.length > 0) {
    //   portTags.push(
    //     `Ephemeral Ports: ${firstFiveEphemeralPorts.join(', ')}${
    //       extraEphemeralCount > 0 ? ', +' + extraEphemeralCount + ' more' : ''
    //     }`
    //   );
    // }

    Logger.trace({ portTags }, 'Port Tags Created');
    return portTags;
  }
};

module.exports = {
  doLookup,
  startup,
  validateOptions,
  onMessage: retryEntity
};
