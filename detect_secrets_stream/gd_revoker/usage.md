## Revocation API Usage

**Verify Token**

`curl -X POST https://gd-revoker.whitewater.ibm.com/api/v1/token/<uuid>/verify`

Possible return values...
- `200`, `{'is_live': true, 'message': 'Secret is active'}` if token is active
- `200`, `{'is_live': false, 'message': 'Secret is remediated'}` if token has been remediated
- `200`, `{'is_live': false, 'message': 'Secret was remediated, raw secret was cleaned up.'}` if token has been remediated and raw secret removed due to PI cleanup procedure.
- `404`, `{'is_live': null, 'message': 'Secret not found'}` if token not found
- `200`, `{'is_live': null, 'message': 'Failed to validate secret'}` if error encountered during verification

Response content type is `application/json`.

**Revoke Token**

`curl -X POST https://gd-revoker.whitewater.ibm.com/api/v1/token/<uuid>/revoke`

Possible return values...
- `200`, `{'success': true, 'message': 'Token with uuid <UUID> has been revoked'}` if token was revoked
- `200`, `{'success': true, 'message': 'Token with uuid <UUID> is already inactive due to raw secret been cleaned up'}` if token was already revoked and PI cleaned up prior to API call
- `200`, `{'success': true, 'message': 'Token with uuid <UUID> is already inactive'}` if token was already revoked prior to API call
- `404`, `{'success': false, 'message': 'Token with uuid <UUID> was not found'}` if token not found
- `200`, `{'success': false, 'message': 'Revocation not implemented for token type <TOKEN_TYPE>'}` if token type not yet supported
- `200`, `{'success': false, 'message': 'Failed to revoke token with uuid <UUID>'}` if error encountered during revocation
