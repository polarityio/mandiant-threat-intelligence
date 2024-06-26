const {
  flow,
  keys,
  values,
  zipObject,
  map,
  first,
  omit,
  reduce,
  size,
  negate,
  curry,
  filter,
  eq,
  isEmpty,
  get,
  join,
  split,
  find,
  getOr,
  uniq
} = require('lodash/fp');

/** JSON Transformations */
const transpose2DArray = reduce(
  (agg, [key, value]) => [
    [...agg[0], key],
    [...agg[1], value]
  ],
  [[], []]
);

const or =
  (...[func, ...funcs]) =>
  (x) =>
    func(x) || (funcs.length && or(...funcs)(x));

const and =
  (...[func, ...funcs]) =>
  (x) =>
    func(x) && (funcs.length ? and(...funcs)(x) : true);


const objectPromiseAll = async (obj = { fn1: async () => {} }) => {
  const labels = keys(obj);
  const functions = values(obj);
  const executedFunctions = await Promise.all(map((func) => func(), functions));

  return zipObject(labels, executedFunctions);
};

const asyncObjectReduce = async (func, initAgg, obj) => {
  const nextKey = flow(keys, first)(obj);

  if (!nextKey) return initAgg;

  const newAgg = await func(initAgg, obj[nextKey], nextKey);

  return await asyncObjectReduce(func, newAgg, omit(nextKey, obj));
};

const sleep = async (ms = 2000) => new Promise((r) => setTimeout(r, ms));

const getSetCookies = flow(get('set-cookie'), map(flow(split('; '), first)), join('; '));

const encodeBase64 = (str) => str && Buffer.from(str).toString('base64');

const decodeBase64 = (str) => str && Buffer.from(str, 'base64').toString('ascii');

const encodeHex = (str) => str && Buffer.from(str, 'utf8').toString('hex');

const decodeHex = (str) => str && Buffer.from(str, 'hex').toString('utf8');

/** Infrastructure */

const buildIgnoreResults = map((entity) => ({
  entity,
  data: null
}));

const parseErrorToReadableJson = (error) =>
  JSON.parse(JSON.stringify(error, Object.getOwnPropertyNames(error)));

const findResultsForThisEntity = (thisEntity, resultsWithEntities) =>
  find(({ entity }) => entity.value === thisEntity.value, resultsWithEntities);

const mergeLookupResults = (entities, ...resultsWithEntities) =>
  map((entity) => {
    const resultsForThisEntity = map(
      (resultWithEntity) => findResultsForThisEntity(entity, resultWithEntity),
      resultsWithEntities
    );

    const [result1ForThisEntity, result2ForThisEntity] = resultsForThisEntity;

    const summary = uniq(
      reduce(
        (agg, result) => [...agg, ...getOr([], 'data.summary', result)],
        [],
        resultsForThisEntity
      )
    );
    const details = reduce(
      (agg, result) => ({ ...agg, ...getOr({}, 'data.details', result) }),
      {},
      resultsForThisEntity
    );
    return result1ForThisEntity && result2ForThisEntity
      ? {
          entity,
          data:
            isEmpty(summary) && isEmpty(details)
              ? null
              : {
                  summary,
                  details
                },
          ...reduce(
            (agg, result) => ({ ...agg, ...omit('data', result) }),
            {},
            resultsForThisEntity
          )
        }
      : result1ForThisEntity || result2ForThisEntity || { entity, data: null };
  }, entities);

module.exports = {
  mergeLookupResults,
  objectPromiseAll,
  asyncObjectReduce,
  transpose2DArray,
  parseErrorToReadableJson,
  and,
  or,
  sleep,
  getSetCookies,
  encodeBase64,
  decodeBase64,
  buildIgnoreResults,
  encodeHex,
  decodeHex
};
