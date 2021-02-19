'use strict';

const request = require('request');
const config = require('./config/config');
const async = require('async');
const fs = require('fs');
const _ = require('lodash');
const { legacyTypes } = require('./src/indicator-types');

const tokenCache = new Map();
const MAX_AUTH_RETRIES = 2;
const MAX_RESULTS = 10;

let Logger;
let requestWithDefaults;
let authenticatedRequest;
let previousDomainRegexAsString = '';
let domainBlocklistRegex = null;

const MAX_ENTITIES_PER_LOOKUP = 100;
const MAX_PARALLEL_CVES = 5;

/**
 * Converts Polarity entity types to their respective Mandiant Threat Intel types
 * @param entityObj
 * @returns {string|null}
 */
function entityTypeToIndicatorType(entityObj) {
  if (entityObj.isIP) {
    return 'ip-address';
  }
  if (entityObj.isHash) {
    return 'hash';
  }
  if (entityObj.isEmail) {
    return 'email';
  }
  if (entityObj.isDomain) {
    return 'fqdn';
  }
  return null;
}

/**
 *
 * @param collections (array of arrays)
 * @returns {null|{summary: [], details: {}}}
 */
function getResultObjectDataFields(collections, entityObj) {
  const summary = [];
  const details = [];
  const counts = {};
  let ttps = [];
  const ttpsSet = new Set();
  const intendedEffectsSet = new Set();
  let intendedEffects = [];
  const targetedInformationSet = new Set();
  let targetedInformation = [];
  const MAX_SUMMARY_LIST_SIZE = 3;

  // used to ensure we don't return duplicate results
  const idSet = new Set();

  collections.forEach((collection) => {
    collection.forEach((object) => {
      if (idSet.has(object.id)) {
        return;
      }
      idSet.add(object.id);

      const fireEyeType = object.type;
      const formatter = legacyTypes[fireEyeType];

      if (formatter && typeof formatter.getFields === 'function') {
        const fields = formatter.getFields(object, entityObj);
        const order = formatter.order;
        const displayValue = formatter.displayValue;
        const icon = formatter.icon;

        // Returned types do not always have all fields.  We don't want to return
        // and object if it has no fields.
        if (fields !== null) {
          if (!details[order]) {
            details[order] = {
              displayValue,
              icon,
              total: 0,
              values: []
            };
          }

          if (details[order].values.length < MAX_RESULTS) {
            details[order].values.push(fields);
          }

          details[order].total += 1;

          if (typeof counts[fireEyeType] === 'undefined') {
            counts[fireEyeType] = 1;
          } else {
            counts[fireEyeType]++;
          }
        }
      }

      // Pluck out data for TTP summary tags
      const objectTtps = _.get(object, 'x_fireeye_com_metadata.ttp');
      if (objectTtps) {
        for (let i = 0; i < objectTtps.length; i++) {
          let ttp = objectTtps[i];
          // The API will return empty strings that we need to filter out.  Also test for strings
          // in case the API returns random data.
          if (typeof ttp == 'string' && ttp.length > 0) {
            ttpsSet.add(ttp);
          }
        }
        ttps = [...ttpsSet];
      }

      // Pluck out data for intended effect summary tags
      const objectIntendedEffects = _.get(object, 'x_fireeye_com_metadata.intended_effect');
      if (objectIntendedEffects) {
        for (let i = 0; i < objectIntendedEffects.length; i++) {
          let effect = objectIntendedEffects[i];
          // The API will return empty strings that we need to filter out.  Also test for strings
          // in case the API returns random data.
          if (typeof effect == 'string' && effect.length > 0) {
            intendedEffectsSet.add(effect);
          }
        }
        intendedEffects = [...intendedEffectsSet];
      }

      // Pluck out data for targeted information summary tags
      const objectTargetedInformation = _.get(object, 'x_fireeye_com_metadata.targeted_information');
      if (objectTargetedInformation) {
        for (let i = 0; i < objectTargetedInformation.length; i++) {
          let effect = objectTargetedInformation[i];
          // The API will return empty strings that we need to filter out.  Also test for strings
          // in case the API returns random data.
          if (typeof effect == 'string' && effect.length > 0) {
            targetedInformationSet.add(effect);
          }
        }
        targetedInformation = [...targetedInformationSet];
      }
    });
  });

  Object.keys(counts).forEach((type) => {
    // Only show reports count if there is more than 1
    if (type === 'report' && counts[type] === 1) {
      return;
    }
    summary.push(`${legacyTypes[type].displayValue}: ${counts[type]}`);
  });

  if (ttps.length > 0) {
    summary.push(
      `TTP: ${ttps.slice(0, MAX_SUMMARY_LIST_SIZE).join(', ')}${
        ttps.length > MAX_SUMMARY_LIST_SIZE ? ' +' + (ttps.length - MAX_SUMMARY_LIST_SIZE) : ''
      }`
    );
  }

  if (intendedEffects.length > 0) {
    summary.push(
      `Intended Effect: ${intendedEffects.slice(0, MAX_SUMMARY_LIST_SIZE).join(', ')}${
        intendedEffects.length > MAX_SUMMARY_LIST_SIZE ? ' +' + (intendedEffects.length - MAX_SUMMARY_LIST_SIZE) : ''
      }`
    );
  }

  if (targetedInformation.length > 0) {
    summary.push(
      `Targeted Info: ${targetedInformation.slice(0, MAX_SUMMARY_LIST_SIZE).join(', ')}${
        targetedInformation.length > MAX_SUMMARY_LIST_SIZE
          ? ' +' + (targetedInformation.length - MAX_SUMMARY_LIST_SIZE)
          : ''
      }`
    );
  }

  if (Object.keys(details).length > 0) {
    return { summary, details };
  } else {
    return null;
  }
}

function startup(logger) {
  Logger = logger;
  let defaults = {
    json: true
  };

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

  authenticatedRequest = (options, requestOptions, cb, requestCounter = 0) => {
    if (requestCounter === MAX_AUTH_RETRIES) {
      // We reached the maximum number of auth retries
      return cb({
        detail: `Attempted to authenticate ${MAX_AUTH_RETRIES} times but failed authentication`
      });
    }

    createToken(options, function (err, token) {
      if (err) {
        Logger.error({ err: err }, 'Error getting token');
        return cb({
          err: err,
          detail: 'Error creating authentication token'
        });
      }

      requestOptions.headers = {
        Accept: 'application/vnd.oasis.stix+json; version=2.1',
        'X-App-Name': 'Polarity',
        Authorization: `Bearer ${token}`
      };

      Logger.trace({ requestOptions }, 'Request');
      requestWithDefaults(requestOptions, (err, resp, body) => {
        if (err) {
          return cb(err, resp, body);
        }

        if (resp.statusCode === 403) {
          // Unable to authenticate so we attempt to get a new token
          invalidateToken(options);
          authenticatedRequest(options, requestOptions, cb, ++requestCounter);
          return;
        }

        let restError = _handleRestErrors(resp, body);
        if (restError) {
          return cb(restError);
        }

        cb(null, resp, body);
      });
    });
  };
}

function _setupRegexBlocklists(options) {
  if (options.domainBlocklistRegex !== previousDomainRegexAsString && options.domainBlocklistRegex.length === 0) {
    Logger.debug('Removing Domain Blocklist Regex Filtering');
    previousDomainRegexAsString = '';
    domainBlocklistRegex = null;
  } else {
    if (options.domainBlocklistRegex !== previousDomainRegexAsString) {
      previousDomainRegexAsString = options.domainBlocklistRegex;
      Logger.debug({ domainBlocklistRegex: previousDomainRegexAsString }, 'Modifying Domain Blocklist Regex');
      domainBlocklistRegex = new RegExp(options.domainBlocklistRegex, 'i');
    }
  }
}

function getTokenFromCache(options) {
  return tokenCache.get(options.publicKey + options.privateKey);
}

function setTokenInCache(options, token) {
  Logger.trace({ token: token }, 'Set Token for Auth');
  tokenCache.set(options.publicKey + options.privateKey, token);
}

function invalidateToken(options) {
  Logger.trace('Invalidating Token');
  tokenCache.delete(options.publicKey + options.privateKey);
}

function createToken(options, cb) {
  let token = getTokenFromCache(options);
  if (token) {
    Logger.trace({ token: token }, 'Returning token from Cache');
    cb(null, token);
  } else {
    let requestOptions = {
      uri: options.uri + '/token',
      method: 'POST',
      form: {
        grant_type: 'client_credentials'
      },
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      auth: {
        username: options.publicKey,
        password: options.privateKey
      },
      json: true
    };

    Logger.trace({ request: requestOptions }, 'Generating new token');

    requestWithDefaults(requestOptions, function (err, response, body) {
      if (err) {
        return cb(err);
      }

      let restError = _handleRestErrors(response, body);

      if (restError) {
        Logger.trace({ restError: restError }, 'REST Error generating token');
        cb(restError);
        return;
      }
      const token = body.access_token;
      setTokenInCache(options, token);

      cb(null, token);
    });
  }
}

/**
 * Takes a "chunk" of entity objects and converts them into an array of request objects which are used to
 * query the FireEye API.
 * @param lookupChunk
 * @returns {[]}
 */
function getChunkQuery(lookupChunk) {
  const queries = [];
  const searchedEntities = new Map();
  for (let i = 0; i < lookupChunk.length; i++) {
    const entityObj = lookupChunk[i];
    searchedEntities.set(entityObj.value.toLowerCase(), entityObj);
    const object_type = entityTypeToIndicatorType(entityObj);
    if (object_type !== null) {
      queries.push({
        object_type,
        value: [entityObj.value],
        extended: true
      });
    }
  }
  return {
    searchedEntities,
    query: {
      requests: queries
    }
  };
}

async function doLookup(entities, options, cb) {
  _setupRegexBlocklists(options);
  let { lookupResults, filteredEntities, cveEntities } = getFilteredEntities(entities, options);
  const lookupChunks = _.chunk(filteredEntities, MAX_ENTITIES_PER_LOOKUP);

  try {
    for await (let lookupChunk of lookupChunks) {
      const { searchedEntities, query } = getChunkQuery(lookupChunk);
      Logger.info({ query }, 'QUERY');
      if (query.length === 0) {
        return;
      }
      const results = await _searchBulkIndicators(query, options);
      const foundEntities = Object.keys(results);
      Logger.info({ foundEntities }, 'Found Entities');
      foundEntities.forEach((entity) => {
        const entityLower = entity.toLowerCase();
        const entityObj = searchedEntities.get(entityLower);
        const indicator = results[entityLower];
        const mScore = getMScore(indicator);
        if (mScore >= options.minimumMScore) {
          lookupResults.push({
            entity: entityObj,
            data: {
              summary: _getSummaryTags(indicator),
              details: indicator
            }
          });
          // Remove the entity that had a result so we can figure out which entities
          // did not have any hits.
          searchedEntities.delete(entityLower);
        }
      });

      for (let noResultEntity of searchedEntities.values()) {
        lookupResults.push({
          entity: noResultEntity,
          data: null
        });
      }
    }

    if (cveEntities.length > 0) {
      const cveResults = await lookupCveEntities(cveEntities, options);
      for (let i = 0; i < cveResults.length; i++) {
        lookupResults.push(cveResults[i]);
      }
    }

    cb(null, lookupResults);
  } catch (lookupError) {
    Logger.error(lookupError, 'doLookup Error');
    cb(lookupError);
  }
}

/**
 * CVE entities have to be looked up
 *
 * @param cveEntities
 * @param options
 * @returns {Promise<unknown>}
 */
async function lookupCveEntities(cveEntities, options) {
  let cveResults = [];
  let tasks = [];
  cveEntities.forEach((entityObj) => {
    tasks.push((done) => {
      _searchCollections(entityObj, options, (err, objects) => {
        done(err, {
          entity: entityObj,
          objects
        });
      });
    });
  });

  return new Promise((resolve, reject) => {
    async.parallelLimit(tasks, MAX_PARALLEL_CVES, (err, results) => {
      if (err) {
        return reject(err);
      }

      results.forEach((result) => {
        if (result.length === 0) {
          cveResults.push({
            entity: result.entity,
            data: null
          });
        } else {
          cveResults.push({
            entity: result.entity,
            data: getResultObjectDataFields([result.objects], result.entity)
          });
        }
      });

      resolve(cveResults);
    });
  });
}

/**
 * Removes any entities that should be filtered out based on blocklists and also adds a
 * lookup miss for those entities to improve caching.
 *
 * @param entities {Array} array of entity objects to be looked up
 * @param options
 * @returns {{filteredEntities: [], cveEntities: [], lookupResults: []}}
 * filteredEntities: non-cve entities for lookup (has blocklisted entities removed)
 * lookupResults: lookup result objects for misses (i.e., blocked entities)
 * cveEntities: cve entities for lookup (we need these separate as they have to be looked up via a different endpoint)
 */
function getFilteredEntities(entities, options) {
  let lookupResults = [];
  let filteredEntities = [];
  let cveEntities = [];
  const blockList = options.blocklist.toLowerCase();
  for (let i = 0; i < entities.length; i++) {
    const entityObj = entities[i];
    if (blockList.includes(entityObj.value.toLowerCase())) {
      Logger.debug({ entity: entityObj.value }, 'Ignored BlockListed Entity Lookup');
      lookupResults.push({
        entity: entityObj,
        data: null
      });
    } else if (entityObj.isDomain && domainBlocklistRegex !== null && domainBlocklistRegex.test(entityObj.value)) {
      Logger.debug({ domain: entityObj.value }, 'Ignored BlockListed Domain Lookup');
      lookupResults.push({
        entity: entityObj,
        data: null
      });
    } else if (entityObj.type === 'cve') {
      cveEntities.push(entityObj);
    } else {
      filteredEntities.push(entityObj);
    }
  }

  return { lookupResults, filteredEntities, cveEntities };
}

function getMScore(indicator) {
  if (indicator.indicator_verdict && typeof indicator.indicator_verdict.mscore !== 'undefined') {
    return indicator.indicator_verdict.mscore;
  } else {
    Logger.warn({ indicator }, 'Could not find valid MScore for indicator');
    return 0;
  }
}

function _getSummaryTags(indicator) {
  let tags = [];
  if (indicator.indicator_verdict && indicator.indicator_verdict.mscore) {
    let mscore = indicator.indicator_verdict.mscore;
    // Adds the conclusion which is typically one of "malicious", "indeterminate", or "benign"
    if (indicator.analysis_conclusion) {
      mscore += ` (${indicator.analysis_conclusion})`;
    }
    tags.push(`MScore: ${mscore}`);
  }

  let threatActor = _.get(indicator, 'attributed_associations.threat_actors.0.name');
  if (threatActor) {
    tags.push(`Actor: ${threatActor}`);
  }

  let malware = _.get(indicator, 'attributed_associations.malware_families.0.name.value');
  if (malware) {
    tags.push(`Malware: ${malware}`);
  }

  if (indicator.external_references && indicator.external_references.length) {
    tags.push(`Reports: ${indicator.external_references.length}`);
  }

  return tags;
}

function _createQuery(entityObj, options) {
  if (entityObj.type === 'cve') {
    return [
      {
        type: 'vulnerability',
        query: `name = '${entityObj.value}'`
      }
    ];
  }

  if (entityObj.isIPv4) {
    return [
      {
        type: 'ipv4-addr',
        query: `value = '${entityObj.value}'`
      }
    ];
  }

  if (entityObj.isMD5) {
    return [
      {
        type: 'file',
        query: `hashes.MD5 = '${entityObj.value}'`
      }
    ];
  }

  if (entityObj.isSHA1) {
    return [
      {
        type: 'file',
        query: `hashes.SHA-1 = '${entityObj.value}'`
      }
    ];
  }

  if (entityObj.isSHA256) {
    return [
      {
        type: 'file',
        query: `hashes.SHA-256 = '${entityObj.value}'`
      }
    ];
  }

  if (entityObj.isDomain) {
    let query = `value = '${entityObj.value}'`;
    if (!entityObj.value.startsWith('www')) {
      query += ` OR value = 'www.${entityObj.value}'`;
    }

    return [
      {
        type: 'domain-name',
        query: query
      }
    ];
  }

  if (entityObj.isEmail) {
    return [
      {
        type: 'email-addr',
        query: `value = '${entityObj.value}'`
      }
    ];
  }
}

/**
 * Returns an object where the top level keys are the entity values that have results (lowercased)
 * {
 *   "8.8.8.8": {
 *     // data on entity
 *   },
 *   "sample.com": {
 *     // data on entity
 *   }
 * }
 * @param chunkQuery
 * @param options
 * @returns {Promise<unknown>}
 * @private
 */
async function _searchBulkIndicators(chunkQuery, options) {
  return new Promise((resolve, reject) => {
    let requestOptions = {
      uri: `${options.uri}/collections/indicators/objects`,
      method: 'POST',
      body: chunkQuery
    };

    Logger.trace({ request: requestOptions }, 'collection indicator search bulk request options');

    authenticatedRequest(options, requestOptions, function (err, response, body) {
      if (err) {
        Logger.trace({ err: err, response: response }, 'Error running collection indicator bulk search');
        return reject(err);
      }

      Logger.trace({ data: body }, 'Collection Indicator Bulk Search Body');
      // body.data contains an object keyed on values. If there are no results body.data will be an empty
      // object.
      resolve(body.data);
    });
  });
}

/**
 * Used specifically to search for CVEs which cannot use the bulk endpoint.  Returns a completely different
 * format than the bulk endpoint which needs custom handling.  We refer to this as the "legacy" endpoint in
 * this code base.
 * @param entityObj
 * @param options
 * @param cb
 * @private
 */
function _searchCollections(entityObj, options, cb) {
  let requestOptions = {
    uri: `${options.uri}/collections/search`,
    method: 'POST',
    body: {
      queries: _createQuery(entityObj, options),
      include_connected_objects: true,
      connected_objects: [
        {
          connection_type: 'relationship',
          object_type: 'malware'
        },
        {
          connection_type: 'relationship',
          object_type: 'threat-actor'
        },
        {
          connection_type: 'reference',
          object_type: 'report'
        }
      ],
      // Note that this limit only applies to the number of objects returned that are not being
      // returned because they are a connected object.  There does not appear to be a way
      // to limit the number of connected objects returned.  We limit the number of connected
      // objects we return to the Overlay Window in post processing.
      limit: MAX_RESULTS,
      offset: 0
    }
  };

  Logger.trace({ request: requestOptions }, 'collection search request options');

  authenticatedRequest(options, requestOptions, function (err, response, body) {
    if (err) {
      Logger.trace({ err: err, response: response }, 'Error running collection search');
      return cb(err);
    }

    Logger.trace({ data: body }, 'Collection Search Body');

    if (!body || !Array.isArray(body.objects) || body.objects.length === 0) {
      // this is a miss
      return cb(null, []);
    }

    cb(null, body.objects);
  });
}

function _handleRestErrors(response, body) {
  switch (response.statusCode) {
    case 200:
    case 204: //no content (i.e., a miss)
      return;
    case 403:
      return _createJsonErrorPayload(
        'Forbidden -- User is not authorized to access this resource with an explicit deny.',
        null,
        '403',
        '1',
        'Forbidden',
        {
          body: body
        }
      );
    case 400:
      return _createJsonErrorPayload('Bad Request -- Your request is invalid.', null, '400', '2', 'Bad Request', {
        body: body
      });
    case 401:
      return _createJsonErrorPayload(
        'Unauthorized -- Your account is expired or the dates are wrong.',
        null,
        '401',
        '3',
        'Conflict',
        {
          body: body
        }
      );
    case 502:
      return _createJsonErrorPayload(
        'Gateway Error -- We had a problem with the Mandiant gateway server, please let us know.\t',
        null,
        '502',
        '4',
        'Mandiant Service Unavailable',
        {
          body: body
        }
      );
    case 504:
      return _createJsonErrorPayload(
        'Gateway Error -- We had a problem with the Mandiant gateway server, please let us know.\t',
        null,
        '504',
        '5',
        'Mandiant Service Unavailable',
        {
          body: body
        }
      );
    case 500:
      return _createJsonErrorPayload(
        'Internal Server Error -- We had a problem with the Mandiant application server, please let us know.',
        null,
        '500',
        '6',
        'Internal Mandiant Service Error',
        {
          body: body
        }
      );
  }

  return _createJsonErrorPayload(
    'Unexpected HTTP Response Status Code',
    null,
    response.statusCode,
    '7',
    'Unexpected HTTP Error',
    {
      body: body
    }
  );
}

// function that takes the ErrorObject and passes the error message to the notification window
function _createJsonErrorPayload(msg, pointer, httpCode, code, title, meta) {
  return {
    errors: [_createJsonErrorObject(msg, pointer, httpCode, code, title, meta)]
  };
}

function _createJsonErrorObject(msg, pointer, httpCode, code, title, meta) {
  let error = {
    detail: msg,
    status: httpCode.toString(),
    title: title,
    code: 'FEINT ' + code.toString()
  };

  if (pointer) {
    error.source = {
      pointer: pointer
    };
  }

  if (meta) {
    error.meta = meta;
  }

  return error;
}

function validateOptions(userOptions, cb) {
  let errors = [];
  if (
    typeof userOptions.uri.value !== 'string' ||
    (typeof userOptions.uri.value === 'string' && userOptions.uri.value.length === 0)
  ) {
    errors.push({
      key: 'uri',
      message: 'You must provide a valid REST Url'
    });
  }

  if (
    typeof userOptions.publicKey.value !== 'string' ||
    (typeof userOptions.publicKey.value === 'string' && userOptions.publicKey.value.length === 0)
  ) {
    errors.push({
      key: 'publicKey',
      message: 'You must provide a valid Mandiant Threat Intelligence API public key'
    });
  }

  if (
    typeof userOptions.privateKey.value !== 'string' ||
    (typeof userOptions.privateKey.value === 'string' && userOptions.privateKey.value.length === 0)
  ) {
    errors.push({
      key: 'privateKey',
      message: 'You must provide a valid Mandiant Threat Intelligence API private key'
    });
  }

  if (userOptions.minimumMScore.value < 0 || userOptions.minimumMScore.value > 100) {
    errors.push({
      key: 'minimumMScore',
      message: 'The Minimum MScore must be between 0 and 100'
    });
  }

  cb(null, errors);
}

module.exports = {
  doLookup,
  startup,
  validateOptions
};
