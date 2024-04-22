const {
  mergeAll,
  isEmpty,
  omit,
  map,
  flow,
  get,
  mapValues,
  values,
  size,
  flatten
} = require('lodash/fp');
const { getLogger } = require('../logging');

const { authenticatedRequest } = require('../request');

const searchAttackPatterns = async (threatActorIds, options) =>
  mergeAll(
    await Promise.all(
      map(
        async (threatActorId) =>
          new Promise((resolve, reject) => {
            const Logger = getLogger();

            let requestOptions = {
              url: `${options.urlV4}/v4/actor/${threatActorId}/attack-pattern`,
              headers: {
                Accept: 'application/json'
              }
            };

            authenticatedRequest(options, requestOptions, function (err, response, body) {
              if (err && get('statusCode', response) !== 404) {
                Logger.trace(
                  { err: err, response: response },
                  'Error running Threat Actor'
                );
                return reject(err);
              }

              const attackPatternsResults = omit('error', body);
              if (isEmpty(attackPatternsResults)) return resolve();

              const groupedAttackPatterns =
                getAttackPatternsInAttackGroups(attackPatternsResults);

              resolve({
                [threatActorId]: groupedAttackPatterns,
                [`${threatActorId}-count`]: flow(
                  values,
                  flatten,
                  size
                )(groupedAttackPatterns)
              });
            });
          }),
        threatActorIds
      )
    )
  );

const getAttackPatternsInAttackGroups = (attackPatternsResults) => {
  const attackPatternsById = get('attack-patterns', attackPatternsResults);

  const attackPatternIdGroups = get(
    'threat-actors.0.attack-patterns',
    attackPatternsResults
  );

  const attackPatternsInAttackGroups = mapValues(
    map((attack) => ({
      ...get(attack.id, attackPatternsById),
      ...(attack.sub_techniques && {
        subTechniques: map(
          (subTechnique) => ({
            ...get(subTechnique.id, attackPatternsById)
          }),
          attack.sub_techniques
        )
      })
    })),
    attackPatternIdGroups
  );

  return attackPatternsInAttackGroups;
};

module.exports = searchAttackPatterns;
