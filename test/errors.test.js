const nock = require('nock');
const { doLookup, startup } = require('../integration');

const options = {
  uri: 'https://api.intelligence.fireeye.com',
  publicKey: 'publicKey',
  privateKey: 'privateKey',
  minimumMScore: 51,
  blocklist: '',
  domainBlocklistRegex: '',
  maxConcurrent: 20,
  minTime: 100
};

const ip = {
  type: 'IPv4',
  value: '8.8.8.8',
  isPrivateIP: false,
  isIPv4: true,
  isIP: true
};

const cve = {
  type: 'cve',
  value: 'CVE-2008-4250'
};

const Logger = {
  trace: (args, msg) => {
    console.info(msg, args);
  },
  info: (args, msg) => {
    console.info(msg, args);
  },
  error: (args, msg) => {
    console.info(msg, args);
  },
  debug: (args, msg) => {
    console.info(msg, args);
  },
  warn: (args, msg) => {
    console.info(msg, args);
  }
};

const emptyLogger = {
  trace: () => {},
  info: () => {},
  error: () => {},
  debug: () => {},
  warn: () => {}
};

let scope;
const useInternalLogger = false;
beforeAll(() => {
  startup(useInternalLogger ? Logger : emptyLogger);
});

const buildErrorTest = (describeMessage, route, entity, defaultSuccessRoutes = []) =>
  describe(describeMessage, () => {
    beforeEach(() => {
      scope = nock(options.uri).post('/token').reply(200, 'Nock token');
      defaultSuccessRoutes.forEach((successRoute) => scope.post(successRoute).reply(200, {}));
    });

    const testDoLookup = (testMethod, errorMessageString, done) => {
      doLookup([entity], options, (err, lookupResults) => {
        // console.info(JSON.stringify({ err, lookupResults }, null, 4));
        testMethod(err, lookupResults, errorMessageString);
        done();
      });
    };
    test('502 response should result in `isGatewayTimeout`', (done) => {
      scope.post(route).reply(502);

      testDoLookup(testForRetryError, 'Gateway Error', done);
    });
    test('504 response should result in `isGatewayTimeout`', (done) => {
      scope.post(route).reply(504);

      testDoLookup(testForRetryError, 'Gateway Error', done);
    });
    test('ECONNRESET response should result in `isConnectionReset`', (done) => {
      scope.post(route).replyWithError({ code: 'ECONNRESET' });

      testDoLookup(testForRetryError, 'Connection Reset', done);
    });
    test('401 response should result in `Unauthorized` Error', (done) => {
      scope.post(route).reply(401);

      testDoLookup(testForError, 'Unauthorized', done);
    });
    test('400 response should result in `Bad Request` Error', (done) => {
      scope.post(route).reply(400);

      testDoLookup(testForError, 'Bad Request', done);
    });
  });

const testForRetryError = (err, lookupResults, messageContainsString) => {
  expect(lookupResults.length).toBe(1);
  const data = lookupResults[0].data;
  const errorMessage = data.details.errorMessage;
  expect(data.summary[0]).toBe('Search Returned Error');
  expect(errorMessage).toBeDefined();
  expect(errorMessage).toEqual(expect.stringContaining(messageContainsString));
};

const testForError = (err, lookupResults, messageContainsString) => {
  expect(err.errors.length).toBe(1);
  expect(err.errors[0].detail).toBeDefined();
  expect(err.errors[0].detail).toEqual(expect.stringContaining(messageContainsString));
};

buildErrorTest('When searching for Indicators:', '/collections/indicators/objects', ip);
buildErrorTest('When searching for Collections:', '/collections/search', cve, ['/collections/indicators/objects']);
