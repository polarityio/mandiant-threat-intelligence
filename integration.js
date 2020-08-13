'use strict';

const request = require('request');
const config = require('./config/config');
const async = require('async');
const fs = require('fs');
const _ = require('lodash');

const tokenCache = new Map();
const MAX_AUTH_RETRIES = 2;
const MAX_RESULTS = 10;

let Logger;
let requestWithDefaults;
let authenticatedRequest;
let previousDomainRegexAsString = '';
let domainBlocklistRegex = null;

const BASE_WEB_URL = 'https://intelligence.fireeye.com';

const fireEyeTypes = {
  malware: {
    displayValue: 'Malware',
    icon: 'bug',
    order: 3,
    getFields: (malware) => {
      return {
        link: {
          display: 'Search in FireEye Intel',
          url: `${BASE_WEB_URL}/search?search=malware%20is%20${malware.name}`
        },
        fields: [
          {
            key: 'Name',
            value: malware.name
          },
          {
            key: 'Labels',
            value: Array.isArray(malware.labels) ? malware.labels : []
          },
          {
            key: 'Malware Types',
            value: Array.isArray(malware.malware_types) ? malware.malware_types : []
          },
          {
            key: 'Is Family',
            value: malware.is_family
          },
          {
            key: 'OS Execution Envs',
            value: Array.isArray(malware.os_execution_envs) ? malware.os_execution_envs : []
          },
          {
            key: 'Associated Detection Names',
            nested: true,
            value: malware.x_fireeye_com_associated_detection_names
          },
          {
            key: 'Description',
            value: malware.description
          }
        ]
      };
    }
  },
  indicator: {
    displayValue: 'Indicators',
    icon: 'bullseye',
    order: 1,
    getFields: (indicator, entityObj) => {
      return {
        link: {
          display: 'Search in FireEye Intel',
          url: `${BASE_WEB_URL}/search?search=indicator%20${entityTypeToIndicatorType(entityObj)}%20is${
            entityObj.value
          }`
        },
        fields: [
          {
            key: 'Types',
            value: indicator.indicator_types
          },
          {
            key: 'Confidence',
            value: indicator.confidence
          },
          {
            key: 'Pattern',
            value: indicator.pattern
          },
          {
            key: 'Labels',
            value: indicator.labels
          },
          {
            key: 'Metadata',
            nested: true,
            value: indicator.x_fireeye_com_metadata
          }
        ]
      };
    }
  },
  'threat-actor': {
    displayValue: 'Threat Actors',
    icon: 'user-secret',
    order: 2,
    getFields: (actor) => {
      return {
        link: {
          display: 'Search in FireEye Intel',
          url: `${BASE_WEB_URL}/search?search=actor%20is%20${actor.name}&exclude_indicator_reports=false`
        },
        fields: [
          {
            key: 'Name',
            value: actor.name
          },

          {
            key: 'id',
            value: actor.id
          },
          {
            key: 'Labels',
            value: Array.isArray(actor.labels) ? actor.labels : []
          },
          {
            key: 'Aliases',
            value: Array.isArray(actor.aliases) ? actor.aliases : []
          },
          {
            key: 'Threat Actor Types',
            value: Array.isArray(actor.threatActorTypes) ? actor.threatActorTypes : []
          },
          {
            key: 'Description',
            value: actor.description
          }
        ]
      };
    }
  },
  report: {
    displayValue: 'Reports',
    icon: 'book',
    order: 0,
    getFields: (report) => {
      return {
        link: {
          display: 'View Report in FireEye Intel',
          url:
            report && report.x_fireeye_com_tracking_info && report.x_fireeye_com_tracking_info.document_id
              ? `${BASE_WEB_URL}/reports/${report.x_fireeye_com_tracking_info.document_id}`
              : null
        },
        fields: [
          {
            key: 'Name',
            value: report.name
          },
          {
            key: 'id',
            value: report.id
          },
          {
            key: 'Labels',
            value: report.labels
          },
          {
            key: 'Published',
            value: report.published
          },
          {
            key: 'Fireeye Metadata',
            nested: true,
            value: report.x_fireeye_com_metadata
          },
          {
            key: 'Description',
            value: report.description
          }
        ]
      };
    }
  },
  vulnerability: {
    displayValue: 'Vulnerabilities',
    icon: 'spider',
    order: 4,
    getFields: (vuln, entityObj) => {
      // Only return the vulnerability if Fireeye has a score for it
      if (Array.isArray(vuln.x_fireeye_com_vulnerability_score)) {
        return {
          link: {
            display: 'Search in FireEye Intel',
            url: `${BASE_WEB_URL}/search?search=${entityObj.value}`
          },
          fields: [
            {
              key: 'id',
              value: vuln.id
            },
            {
              key: 'Scores',
              nested: true,
              value: Array.isArray(vuln.x_fireeye_com_vulnerability_score)
                ? vuln.x_fireeye_com_vulnerability_score.map((vuln) => {
                    return {
                      Vector: _.get(vuln, 'vector'),
                      'Temporal Score': _.get(vuln, 'temporal_metrics.temporal_score'),
                      'Base Score': _.get(vuln, 'base_metrics.base_score')
                    };
                  })
                : []
            }
          ]
        };
      } else {
        return null;
      }
    }
  },
  file: {
    displayValue: 'Files',
    icon: 'file',
    order: 5,
    getFields: (file, entityObj) => {
      return {
        link: {
          display: 'Search in FireEye Intel',
          url: `${BASE_WEB_URL}/search?search=${entityObj.value}`
        },
        fields: [
          {
            key: 'Name',
            value: file.name
          },
          {
            key: 'id',
            value: file.id
          },
          {
            key: 'Size',
            value: file.size
          }
        ]
      };
    }
  },
  'email-addr': {
    displayValue: 'Email',
    icon: 'email',
    order: 6,
    getFields: (email, entityObj) => {
      return {
        link: {
          display: 'Search in FireEye Intel',
          url: `${BASE_WEB_URL}/search?search=${entityObj.value}`
        },
        fields: [
          {
            key: 'id',
            value: email.id
          },
          {
            key: 'Modified',
            value: email.modified
          }
        ]
      };
    }
  },
  'x-fireeye-com-remedy-action': {
    displayValue: 'Remedies',
    icon: 'prescription-bottle-alt',
    order: 7,
    getFields: (remedy) => {
      return {
        link: null,
        fields: [
          {
            key: 'Type',
            value: remedy.remedy_type
          },
          {
            key: 'id',
            value: remedy.id
          },
          {
            key: 'References',
            nested: true,
            value: Array.isArray(remedy.external_references) ? remedy.external_references : []
          },
          {
            key: 'Description',
            value: remedy.description
          }
        ]
      };
    }
  }
};

function entityTypeToIndicatorType(entityObj) {
  if (entityObj.isIP) {
    return 'IP';
  }
  if (entityObj.isMD5) {
    return 'MD5';
  }
  if (entityObj.isSHA1) {
    return 'SHA1';
  }
  if (entityObj.isSHA256) {
    return 'SHA256';
  }
  if (entityObj.isEmail) {
    return 'Email Sender';
  }
  if (entityObj.isDomain) {
    return 'Domain';
  }
  if (entityObj.type === 'cve') {
    return 'CVE';
  }
  return '';
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
  // used to ensure we don't return duplicate results
  const idSet = new Set();

  collections.forEach((collection) => {
    collection.forEach((object) => {
      if(idSet.has(object.id)){
        return;
      }
      idSet.add(object.id);

      const fireEyeType = object.type;
      const formatter = fireEyeTypes[fireEyeType];

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
    });
  });

  Object.keys(counts).forEach((type) => {
    summary.push(`${fireEyeTypes[type].displayValue}: ${counts[type]}`);
  });

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

function doLookup(entities, options, cb) {
  _setupRegexBlocklists(options);

  let lookupResults = [];

  async.each(
    entities,
    (entityObj, next) => {
      if (options.blocklist.toLowerCase().includes(entityObj.value.toLowerCase())) {
        Logger.debug({ entity: entityObj.value }, 'Ignored BlockListed Entity Lookup');
        lookupResults.push({
          entity: entityObj,
          data: null
        });
        return next(null);
      } else if (entityObj.isDomain) {
        if (domainBlocklistRegex !== null) {
          if (domainBlocklistRegex.test(entityObj.value)) {
            Logger.debug({ domain: entityObj.value }, 'Ignored BlockListed Domain Lookup');
            lookupResults.push({
              entity: entityObj,
              data: null
            });
            return next(null);
          }
        }
      }

      _lookupEntity(entityObj, options, function (err, result) {
        if (err) {
          next(err);
        } else {
          Logger.debug({ results: result }, 'Logging results');
          lookupResults.push(result);
          next(null);
        }
      });
    },
    (err) => {
      cb(err, lookupResults);
    }
  );
}

function _createIndicatorQuery(entityObj, options) {
  if (entityObj.isIP || entityObj.isHash || entityObj.isDomain || entityObj.isEmail || entityObj.type === 'cve') {
    return [
      {
        type: 'indicator',
        query: `pattern LIKE '%${entityObj.value}%'`
      }
    ];
  }
  return null;
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

function _searchIndicators(entityObj, options, cb) {
  const indicatorQuery = _createIndicatorQuery(entityObj, options);

  if(indicatorQuery === null){
    return cb(null, []);
  }

  let requestOptions = {
    uri: `${options.uri}/collections/search`,
    method: 'POST',
    body: {
      queries: indicatorQuery,
      include_connected_objects: true,
      // Note that this limit only applies to the number of objects returned that are not being
      // returned because they are a connected object.  There does not appear to be a way
      // to limit the number of connected objects returned.  We limit the number of connected
      // objects we return to the Overlay Window in post processing.
      limit: MAX_RESULTS,
      offset: 0
    }
  };

  Logger.trace({ request: requestOptions }, 'incident search request options');

  authenticatedRequest(options, requestOptions, function (err, response, body) {
    if (err) {
      Logger.trace({ err: err, response: response }, 'Error running incident search');
      return cb(err);
    }

    Logger.trace({ data: body }, 'Incident Search Body');

    if (!body || !Array.isArray(body.objects) || body.objects.length === 0) {
      // this is a miss
      return cb(null, []);
    }

    cb(null, body.objects);
  });
}

function _searchCollections(entityObj, options, cb) {
  let requestOptions = {
    uri: `${options.uri}/collections/search`,
    method: 'POST',
    body: {
      queries: _createQuery(entityObj, options),
      include_connected_objects: true,
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

function _lookupEntity(entityObj, options, cb) {
  async.parallel(
    {
      indicator: (done) => {
        if (!options.enableIndicatorSearch) {
          return done(null, []);
        }
        _searchIndicators(entityObj, options, done);
      },
      collection: (done) => {
        _searchCollections(entityObj, options, done);
      }
    },
    (err, results) => {
      if(err){
        return cb(err);
      }

      Logger.trace({ results }, 'Search Results');

      if (results.indicator.length === 0 && results.collection.length === 0) {
        cb(null, {
          entity: entityObj,
          data: null
        });
        return;
      }

      cb(null, {
        entity: entityObj,
        data: getResultObjectDataFields([results.indicator, results.collection], entityObj)
      });
    }
  );
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
        'Gateway Error -- We had a problem with the FireEye gateway server, please let us know.\t',
        null,
        '502',
        '4',
        'FireEye Service Unavailable',
        {
          body: body
        }
      );
    case 504:
      return _createJsonErrorPayload(
        'Gateway Error -- We had a problem with the FireEye gateway server, please let us know.\t',
        null,
        '504',
        '5',
        'FireEye Service Unavailable',
        {
          body: body
        }
      );
    case 500:
      return _createJsonErrorPayload(
        'Internal Server Error -- We had a problem with the FireEye application server, please let us know.',
        null,
        '500',
        '6',
        'Internal FireEye Server Error',
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
  Logger.trace(userOptions, 'User Options to Validate');
  let errors = [];
  if (
    typeof userOptions.url.value !== 'string' ||
    (typeof userOptions.url.value === 'string' && userOptions.url.value.length === 0)
  ) {
    errors.push({
      key: 'url',
      message: 'You must provide a Resilient URl'
    });
  }

  if (
    typeof userOptions.orgId.value !== 'string' ||
    (typeof userOptions.orgId.value === 'string' && userOptions.orgId.value.length === 0)
  ) {
    errors.push({
      key: 'orgId',
      message: 'You must provide a Resilient Org ID'
    });
  }

  if (
    typeof userOptions.username.value !== 'string' ||
    (typeof userOptions.username.value === 'string' && userOptions.username.value.length === 0)
  ) {
    errors.push({
      key: 'username',
      message: 'You must provide a Resilient Username'
    });
  }

  if (
    typeof userOptions.password.value !== 'string' ||
    (typeof userOptions.password.value === 'string' && userOptions.password.value.length === 0)
  ) {
    errors.push({
      key: 'password',
      message: 'You must provide a Resilient Password'
    });
  }

  Logger.trace(errors, 'Validated Options');

  cb(null, errors);
}

module.exports = {
  doLookup,
  startup
};
