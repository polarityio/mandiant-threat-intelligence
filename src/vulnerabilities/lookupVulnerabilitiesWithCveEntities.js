const { map, get, flow, chunk, filter, size, flatten } = require('lodash/fp');

const searchVulnerabilities = require('./searchVulnerabilities');
const { getLimiter } = require('../request');

/**
 * CVE entities have to be looked up
 *
 * @param cveEntities
 * @param options
 * @returns {Promise<unknown>}
 */
const lookupVulnerabilitiesWithCveEntities = async (cveEntities, options) => {
  const limitedSearchVulnerabilities = getLimiter(options).wrap(searchVulnerabilities);

  return flatten(await Promise.all(
    flow(
      chunk(10),
      map(async (entityChunk) => {
        try {
          const vulnerabilities = await limitedSearchVulnerabilities(
            entityChunk,
            options
          );

          return associateCveEntitiesWithVulnerabilities(cveEntities, vulnerabilities);
        } catch (error) {
          if (Math.floor(parseInt(get('errors.0.status', error)) / 100) * 100 === 500) {
            return {
              entity: entityObj,
              isVolatile: true,
              data: {
                summary: ['Search Returned Error'],
                details: { errorMessage: get('errors.0.detail', error) }
              }
            };
          }
          throw error;
        }
      })
    )(cveEntities)
  ));
};

const associateCveEntitiesWithVulnerabilities = (cveEntities, vulnerabilities) =>
  map(
    (cveEntity) =>
      flow(
        filter((vulnerability) => cveEntity.value === vulnerability.cve_id),
        (vulnerabilities) => ({
          entity: cveEntity,
          data: !size(vulnerabilities)
            ? null
            : {
              summary: [`Vulns: ${size(vulnerabilities)}`],
              details: { vulnerabilities }
            }
        })
      )(vulnerabilities),
    cveEntities
  );

module.exports = lookupVulnerabilitiesWithCveEntities;
