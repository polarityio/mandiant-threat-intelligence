'use strict';

const { setLogger, getLogger } = require('./src/logging');
const { validateOptions } = require('./src/userOptions');

const getFilteredEntities = require('./src/getFilteredEntities');
const lookupNonCveEntities = require('./src/lookupNonCveEntities');
const lookupCveEntities = require('./src/lookupCveEntities');
const lookupEntities = require('./src/lookupEntities');

async function doLookup(entities, options, cb) {
  const Logger = getLogger();
  Logger.trace({ entities, options }, 'Lookup Entities & Options');

  try {
    let { lookupResults, filteredEntities, cveEntities, customEntities } =
      getFilteredEntities(entities, options);

    const indicatorLookupResults = await lookupNonCveEntities(filteredEntities, options);

    const cveLookupResults = await lookupCveEntities(cveEntities, options);

    const allSearchLookupResults = await lookupEntities(
      filteredEntities,
      cveEntities,
      customEntities,
      indicatorLookupResults,
      cveLookupResults,
      options
    );

    Logger.trace(
      {
        lookupResults,
        filteredEntities,
        cveEntities,
        customEntities,
        allSearchLookupResults
      },
      'Lookup Results'
    );

    cb(null, lookupResults.concat(allSearchLookupResults));
  } catch (lookupError) {
    const error = {
      ...lookupError,
      detail: lookupError.message || 'Command Failed',
      err: JSON.parse(
        JSON.stringify(lookupError, Object.getOwnPropertyNames(lookupError))
      )
    };

    Logger.error(error, 'doLookup Error');
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
