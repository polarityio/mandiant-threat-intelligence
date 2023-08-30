function handleRestErrors(response, body) {
  switch (response.statusCode) {
    case 200:
    case 204: //no content (i.e., a miss)
      return;
    case 404: //no content (i.e., a miss)
      return;
    case 403:
      return _createJsonErrorPayload(
        'Forbidden -- User is not authorized to access this resource with an explicit deny.',
        null,
        '403',
        '1',
        'Forbidden',
        {
          body: body
        }
      );
    case 400:
      return _createJsonErrorPayload('Bad Request -- Your request is invalid.', null, '400', '2', 'Bad Request', {
        body: body
      });
    case 401:
      return _createJsonErrorPayload(
        'Unauthorized -- Your account is expired or the dates are wrong.',
        null,
        '401',
        '3',
        'Conflict',
        {
          body: body
        }
      );
    case 502:
      return _createJsonErrorPayload(
        'Gateway Error -- We had a problem with the Mandiant gateway server.\t',
        null,
        '502',
        '4',
        'Mandiant Service Unavailable',
        {
          body: body
        }
      );
    case 504:
      return _createJsonErrorPayload(
        'Gateway Error -- We had a problem with the Mandiant gateway server.\t',
        null,
        '504',
        '5',
        'Mandiant Service Unavailable',
        {
          body: body
        }
      );
    case 500:
      return _createJsonErrorPayload(
        'Internal Server Error -- We had a problem with the Mandiant application server.',
        null,
        '500',
        '6',
        'Internal Mandiant Service Error',
        {
          body: body
        }
      );
    case 'ECONNRESET':
      return _createJsonErrorPayload(
        'Connection Reset -- We had a problem with the Mandiant application server.',
        null,
        '599',
        '7',
        'Internal Mandiant Service Error',
        {
          body: body
        }
      );
  }

  return _createJsonErrorPayload(
    'Unexpected HTTP Response Status Code',
    null,
    response.statusCode,
    '7',
    'Unexpected HTTP Error',
    {
      body: body
    }
  );
}

// function that takes the ErrorObject and passes the error message to the notification window
function _createJsonErrorPayload(msg, pointer, httpCode, code, title, meta) {
  return {
    errors: [_createJsonErrorObject(msg, pointer, httpCode, code, title, meta)]
  };
}

function _createJsonErrorObject(msg, pointer, httpCode, code, title, meta) {
  let error = {
    detail: msg,
    status: httpCode.toString(),
    title: title,
    code: 'FEINT ' + code.toString()
  };

  if (pointer) {
    error.source = {
      pointer: pointer
    };
  }

  if (meta) {
    error.meta = meta;
  }

  return error;
}

module.exports = handleRestErrors;
