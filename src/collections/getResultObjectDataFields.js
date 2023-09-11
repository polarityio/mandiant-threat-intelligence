
const { get } = require('lodash/fp');
const { getLogger } = require('../logging');
const { legacyTypes, MAX_RESULTS } = require('./indicatorTypes');

/**
 *
 * @param collections (array of arrays)
 * @returns {null|{summary: [], details: {}}}
 */
function getResultObjectDataFields(collections = [], entityObj) {
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
    collection &&
      collection.forEach((object) => {
        if (idSet.has(object.id)) return;
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
        const objectTtps = get(object, 'x_fireeye_com_metadata.ttp');
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
        const objectIntendedEffects = get(object, 'x_fireeye_com_metadata.intended_effect');
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
        const objectTargetedInformation = get(object, 'x_fireeye_com_metadata.targeted_information');
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
    return { summary, details: {
      collections: details
    } };
  } else {
    return null;
  }
}

module.exports = getResultObjectDataFields;