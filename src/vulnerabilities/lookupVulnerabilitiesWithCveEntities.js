const {
  map,
  get,
  flow,
  chunk,
  filter,
  size,
  flatten,
  reduce,
  getOr,
  first,
  gte,
  gt,
  replace
} = require('lodash/fp');

const searchVulnerabilities = require('./searchVulnerabilities');
const sanitizeHtml = require('sanitize-html');
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

  return flatten(
    await Promise.all(
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
    )
  );
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
                details: {
                  vulnerabilities: map(
                    (vuln) => ({
                      ...vuln,
                      ...makeHtmlFieldsSafe(
                        [
                          'description',
                          'analysis',
                          'executive_summary',
                          'vulnerable_products',
                          'workarounds'
                        ],
                        vuln
                      ),
                      workarounds_list: map(
                        sanitizeHtmlString,
                        get('workarounds_list', vuln)
                      )
                    }),
                    vulnerabilities
                  )
                }
              }
        })
      )(vulnerabilities),
    cveEntities
  );

const makeHtmlFieldsSafe = (fields, vuln) =>
  reduce(
    (acc, field) => ({
      ...acc,
      [field]: sanitizeHtmlString(vuln[field] || '')
    }),
    {},
    fields
  );

/**
 * Removes all non ['p', 'ul', 'li', 'b', 'i', 'em', 'strong', 'br'] tags, and takes the 
 * links out of archor tags and hardcodes the url string at the end of that achor tab
 */
const sanitizeHtmlString = (htmlString) => {
  const fieldStringWithDisplayedLinkUrls =
    makeHtmlStringWithDisplayedLinkUrls(htmlString);

  const sanitizedHtmlString = sanitizeHtml(fieldStringWithDisplayedLinkUrls, {
    allowedTags: ['p', 'ul', 'li', 'b', 'i', 'em', 'strong', 'br'],
    allowedAttributes: {}
  });
  return sanitizedHtmlString;
};


const makeHtmlStringWithDisplayedLinkUrls = (htmlString = '') => {
  const firstAnchorStartingTag = first(
    Array.from(htmlString.matchAll(/<a href="([^"]+)">/g))
  );

  if (!firstAnchorStartingTag) {
    return htmlString;
  }

  const firstAnchorStartingTagIndex = htmlString.indexOf(firstAnchorStartingTag[1]);

  const anchorTagClosingTagIndices = map(
    get('index'),
    Array.from(htmlString.matchAll(/<\/\s?a\s?>/g))
  );

  const closestMatchingClosingTagIndex = flow(
    filter(
      (anchorTagClosingTagIndex) => anchorTagClosingTagIndex > firstAnchorStartingTagIndex
    ),
    first
  )(anchorTagClosingTagIndices);

  const htmlStringWithThisDisplayLinkUrl =
    htmlString.slice(0, closestMatchingClosingTagIndex) +
    ` - ${firstAnchorStartingTag[1]}` +
    htmlString.slice(closestMatchingClosingTagIndex);

  const htmlStringWithThisDisplayLinkArchorTagRemoved = replace(
    firstAnchorStartingTag[0],
    '',
    htmlStringWithThisDisplayLinkUrl
  );

  return makeHtmlStringWithDisplayedLinkUrls(
    htmlStringWithThisDisplayLinkArchorTagRemoved
  );
};

module.exports = lookupVulnerabilitiesWithCveEntities;
