const { getLogger } = require('../logging');

const { authenticatedRequest } = require('../request');

const MAX_RESULTS = 10;
/**
 * Used specifically to search for CVEs which cannot use the bulk endpoint.  Returns a completely different
 * format than the bulk endpoint which needs custom handling.  We refer to this as the "legacy" endpoint in
 * this code base.
 * @param entityObj
 * @param options
 * @param cb
 * @private
 */
const searchCollections = async (entityObj, options) =>
  new Promise((resolve, reject) => {
    const Logger = getLogger();

    let requestOptions = {
      uri: `${options.uri}/collections/search`,
      method: 'POST',
      body: {
        queries: createQuery(entityObj, options),
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
        return reject(err);
      }

      Logger.trace({ data: body }, 'Collection Search Body');

      if (!body || !Array.isArray(body.objects) || body.objects.length === 0) return resolve([]);

      resolve(body.objects);
    });
  });

function createQuery(entityObj, options) {
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
module.exports = searchCollections;
