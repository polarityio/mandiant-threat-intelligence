'use strict';

const { setLogger, getLogger } = require('./src/logging');
const { validateOptions } = require('./src/userOptions');

const getFilteredEntities = require('./src/getFilteredEntities');
const lookupNonCveEntities = require('./src/lookupNonCveEntities');
const lookupCveEntities = require('./src/lookupCveEntities');
const { lookupWithSearch } = require('./src/search');
const { mergeLookupResults } = require('./src/dataTransformations');

async function doLookup(entities, options, cb) {
  try {
    let { lookupResults, filteredEntities, cveEntities, customEntities } = getFilteredEntities(
      entities,
      options
    );

    const indicatorLookupResults = await lookupNonCveEntities(filteredEntities, options);

    const cveLookupResults = await lookupCveEntities(cveEntities, options);

    const searchLookupResults = await lookupWithSearch(
      filteredEntities,
      cveEntities,
      customEntities,
      options
    );

    const searchAndOtherLookupResults = mergeLookupResults(
      filteredEntities.concat(cveEntities).concat(customEntities),
      searchLookupResults,
      indicatorLookupResults.concat(cveLookupResults)
    );

    cb(null, lookupResults.concat(searchAndOtherLookupResults));
  } catch (lookupError) {
    const error = {
      ...lookupError,
      detail: lookupError.message || 'Command Failed',
      err: JSON.parse(
        JSON.stringify(lookupError, Object.getOwnPropertyNames(lookupError))
      )
    };

    getLogger().error(error, 'doLookup Error');
    cb(error);
  }
}

function onMessage(payload, options, cb) {
  switch (payload.action) {
    case 'RETRY_LOOKUP':
      doLookup([payload.entity], options, (err, lookupResults) => {
        if (err) {
          Logger.error({ err }, 'Error retrying lookup');
          cb(err);
        } else {
          cb(
            null,
            lookupResults && lookupResults[0] && lookupResults[0].data === null
              ? { data: { summary: ['No Results Found on Retry'] } }
              : lookupResults[0]
          );
        }
      });
      break;
  }
}

module.exports = {
  startup: setLogger,
  validateOptions,
  doLookup,
  onMessage
};
