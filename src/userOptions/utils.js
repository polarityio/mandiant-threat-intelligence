const {
  isEmpty,
  get,
  curry,
  flow,
  split,
  map,
  zipObject,
  trim,
  uniq,
  compact,
  first,
  replace,
  toLower
} = require('lodash/fp');
const { transpose2DArray } = require('../dataTransformations');
const reduce = require('lodash/fp/reduce').convert({ cap: false });

const compareStringLetters = (str1, str2) => {
  const getStringLetters = flow(toLower, replace(/\W/gi, ''));
  return getStringLetters(str1) === getStringLetters(str2);
};

const flattenOptions = (options) =>
  reduce(
    (agg, optionObj, optionKey) => ({ ...agg, [optionKey]: get('value', optionObj) }),
    {},
    options
  );

const validateStringOptions = (stringOptionsErrorMessages, options, otherErrors = []) =>
  reduce((agg, message, optionName) => {
    const isString = typeof options[optionName].value === 'string';
    const isEmptyString = isString && isEmpty(options[optionName].value);

    return !isString || isEmptyString
      ? agg.concat({
          key: optionName,
          message
        })
      : agg;
  }, otherErrors)(stringOptionsErrorMessages);

const splitCommaSeparatedUserOption = curry((key, options) =>
  flow(get(key), split(','), map(trim), compact, uniq)(options)
);

const splitCommaSeparatedUserOptionThenFirst = curry((key, options) => [
  first(splitCommaSeparatedUserOption(key, options))
]);

const splitKeyValueCommaSeparatedUserOption = (key, options) =>
  flow(
    splitCommaSeparatedUserOption(key),
    map(flow(split(':'), map(trim))),
    transpose2DArray,
    ([keys, values]) => zipObject(keys, values)
  )(options);

const splitKeyValueCommaSeparatedUserOptionThenFirst = (key, options) =>
  flow(
    splitCommaSeparatedUserOption(key),
    map(flow(split(':'), map(trim))),
    ([first]) => [first],
    transpose2DArray,
    ([keys, values]) => zipObject(keys, values)
  )(options);

const validateUrlOption = (options, urlKey = 'url', otherValidationErrors = []) => {
  const urlValue = get([urlKey, 'value'], options);

  if (urlValue === undefined) {
    throw new Error(
      `User Option key \`${urlKey}\` is not defined in the config.js.  ` +
        "It's also possible you need to change the package.json version for the client to pick up your `config/config.js` changes."
    );
  }

  let allValidationErrors = otherValidationErrors;
  if (!urlValue) {
    allValidationErrors = allValidationErrors.concat({
      key: urlKey,
      message: '* Required'
    });
  }

  if (urlValue.endsWith('//')) {
    allValidationErrors = allValidationErrors.concat({
      key: urlKey,
      message: 'Url cannot end with a //'
    });
  }

  if (urlValue) {
    try {
      new URL(urlValue);
    } catch (_) {
      allValidationErrors = allValidationErrors.concat({
        key: urlKey,
        message:
          'What is currently provided is not a valid URL. A valid Instance URL is Required.'
      });
    }
  }

  return allValidationErrors;
};
module.exports = {
  compareStringLetters,
  flattenOptions,
  validateStringOptions,
  splitCommaSeparatedUserOption,
  splitKeyValueCommaSeparatedUserOption,
  splitCommaSeparatedUserOptionThenFirst,
  splitKeyValueCommaSeparatedUserOptionThenFirst,
  validateUrlOption
};
