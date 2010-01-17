# A Python library for talking Cascade.

import cgi
import oauth
import simplejson
import sys
import time
import unittest
import urllib
import urllib2
import urlparse

################################################################################
# Constants 
################################################################################

JSON11_ENDPOINT_URL = 'http://mail.yahooapis.com/ws/mail/v1.1/jsonrpc'
OAUTH2_ENDPOINT_URL = 'https://api.login.yahoo.com/oauth/v2'

################################################################################
# Exception classes
################################################################################

class CascadeError(Exception):
    '''An exception class for Cascade errors.'''

    def __init__(self, msg = ''):
        Exception.__init__(self, msg)

class CascadeHTTPError(CascadeError):
    '''An exception class for serve-generated Cascade errors.'''

    def __init__(self, httpResponse):
        self.__httpResponse = httpResponse
        self.__jsonError = None

        if httpResponse.headers.type == 'application/json':
            jo = simplejson.loads(''.join(httpResponse.readlines()))
            self.__jsonError = jo['error']

    def getJSONError(self):
        '''Get a Python object representing the JSON error blob. Only valid if
           the Content-Type of the response is application/json; otherwise,
           returns None.'''

        return self.__error

    def getHTTPStatus(self):
        '''Get the HTTP status code from the response.'''

        return self.__httpResponse.code

    def __str__(self):
        return '%s: %d %s' % (self.__httpResponse.url, self.__httpResponse.code, self.__httpResponse.msg)

################################################################################
# Cascade client classes
################################################################################

class JSON11Client:
    '''A Cascade client that converses over the JSON 1.1 API, authenticated
       by OAuth.'''

    def __init__(self, oaConsumer, oaToken):
        '''Instantiate a new client with the given OAuth parameters.'''

        self.__oaConsumer = oaConsumer
        self.__oaToken = oaToken
        self.__oaSig = oauth.OAuthSignatureMethod_HMAC_SHA1()

    def getToken(self):
        '''Get the OAuthToken for this client. A caller may wish to invoke
           this, as the underlying token may have changed due to access
           token refresh.'''

        return self.__oaToken

    def call(self, method = '', params = [{}]):
        '''Call the given method using the specified parameters (which are
           passed directly as the 'params' value in the JSON payload).
           Returns a result object derived from un-serializing the response
           JSON data. Raises a CascadeHTTPError if problems arise.'''

        for attemptNo in range(0, 2):
            # Construct and sign the request within our retry loop so that
            # we pick up any refresh of the access token
            oaReq = oauth.OAuthRequest(
                http_method = 'POST',
                http_url = JSON11_ENDPOINT_URL,
                parameters = {
                    'oauth_nonce' : oauth.generate_nonce(),
                    'oauth_timestamp' : oauth.generate_timestamp(),
                    'oauth_consumer_key' : self.__oaConsumer.key,
                    'oauth_token' : self.__oaToken.key,
                    'oauth_version' : '1.0'
                }
            )
            oaReq.sign_request(self.__oaSig, self.__oaConsumer, self.__oaToken)

            headers = { 'Content-Type' : 'application/json' }
            headers.update(oaReq.to_header())

            cascadeResp = None
            try:
                cascadeReq = urllib2.Request(
                    url = JSON11_ENDPOINT_URL,
                    data = simplejson.dumps({
                        'method' : method,
                        'params' : params,
                    }),
                    headers = headers
                )

                cascadeResp = urllib2.urlopen(cascadeReq)

                return simplejson.loads(''.join(cascadeResp.readlines()))
            except urllib2.HTTPError, e:
                # If we see something other than a 401 on our first attempt
                # to make the call, give up. Otherwise, attempt to refresh
                # our access token and try again.
                #
                # XXX: I can't get this to work with the Yahoo! OAuth
                #      provider at this point. For some reason, the refresh
                #      works but using the new token yields the same error
                #      (999).
                if attemptNo > 0 or e.code != 999:
                    raise CascadeHTTPError(e)

                self.__oaToken = oauth_refresh_access_token(
                    self.__oaConsumer,
                    self.__oaToken
                )
            finally:
                if cascadeResp:
                    cascadeResp.close()

        # We should never get here.
        assert(False)

################################################################################
# OAuth utility functions
################################################################################

def oauth_get_request_token(oaConsumer, url):
    '''Get an OAuth request token URL to use for verification. Returns a
       tuple of (token, url). The 'url' parameter indicates the destination
       for redirection once the user has validated the request.'''

    oaSig = oauth.OAuthSignatureMethod_HMAC_SHA1()

    oaReq = oauth.OAuthRequest(
        http_method = 'GET',
        http_url = OAUTH2_ENDPOINT_URL + '/get_request_token',
        parameters = {
            'oauth_nonce' : oauth.generate_nonce(),
            'oauth_timestamp' : oauth.generate_timestamp(),
            'oauth_consumer_key' : oaConsumer.key,
            'oauth_version' : '1.0',
            'xoauth_lang_pref' : 'en-us',
            'oauth_callback' : url,
        }
    )

    oaReq.sign_request(oaSig, oaConsumer, None)

    reqTokenResp = None
    try:
        reqTokenResp = urllib2.urlopen(oaReq.to_url())
        reqTokenRespContent = ''.join(reqTokenResp.readlines())

        oaReqToken = oauth.OAuthToken.from_string(reqTokenRespContent)

        return (
            oaReqToken,
            OAUTH2_ENDPOINT_URL + '/request_auth?' +
                urllib.urlencode([('oauth_token', oaReqToken.key)])
        )
    except urllib2.HTTPError, e:
        raise CascadeHTTPError(e)
    finally:
        if reqTokenResp:
            reqTokenResp.close()

def oauth_get_access_token(oaConsumer, oaReqToken):
    '''Get an OAuth access token from the given token (either request or
       access). Returns an oauth.OAuthToken, possibly  with some extra
       instance variables set to reflect presence of OAuth extension
       attributes in the response (e.g.  session handle, expiration time,
       etc). Can be called with an access token to attempt a refresh (which
       still returns a new token).'''

    oaSig = oauth.OAuthSignatureMethod_HMAC_SHA1()

    oaReqParams = {
        'oauth_nonce' : oauth.generate_nonce(),
        'oauth_timestamp' : oauth.generate_timestamp(),
        'oauth_consumer_key' : oaConsumer.key,
        'oauth_token' : oaReqToken.key,
        'oauth_version' : '1.0',
    }

    # If our token has a session handle, add it to our parmeter dictionary.
    # This should only be the case if we're requesting a new access token
    # (i.e. not doing a token refresh, as access tokens do not have a
    # verifier).
    if 'verifier' in oaReqToken.__dict__:
        oaReqParams['oauth_verifier'] = oaReqToken.verifier

    # If our token has a session handle, add it to our parmeter dictionary.
    # This should only be the case if we're doing a token refresh from an
    # access token.
    if 'session_handle' in oaReqToken.__dict__:
        oaReqParams['oauth_session_handle'] = oaReqToken.session_handle

    oaReq = oauth.OAuthRequest(
        http_method = 'GET',
        http_url = OAUTH2_ENDPOINT_URL + '/get_token',
        parameters = oaReqParams
    )

    oaReq.sign_request(oaSig, oaConsumer, oaReqToken)

    accTokenResp = None
    try:
        accTokenResp = urllib2.urlopen(oaReq.to_url())
        accTokenRespContent = ''.join(accTokenResp.readlines())

        accTok = oauth.OAuthToken.from_string(accTokenRespContent)

        # Look for any extra query parameters that provide data from OAuth
        # extensions that we might care about. Specifically, make sure to
        # grab the session handle so that we can refresh the access token.
        accTokParams = cgi.parse_qs(
            accTokenRespContent,
            keep_blank_values = False
        )
        if 'oauth_expires_in' in accTokParams:
            accTok.expires_on = \
                int(time.time()) + \
                int(accTokParams['oauth_expires_in'][0])
        if 'oauth_session_handle' in accTokParams:
            accTok.session_handle = accTokParams['oauth_session_handle'][0]
        if 'oauth_authorization_expires_in' in accTokParams:
            accTok.authorization_expires_on = \
                int(time.time()) + \
                int(accTokParams['oauth_authorization_expires_in'][0])
        if 'xoauth_yahoo_guid' in accTokParams:
            accTok.yahoo_guid = accTokParams['xoauth_yahoo_guid'][0]

        return accTok
    except urllib2.HTTPError, e:
        raise CascadeHTTPError(e)
    finally:
        if accTokenResp:
            accTokenResp.close()

def oauth_refresh_access_token(oaConsumer, oaAccToken):
    '''Refresh the given OAuth access token. Returns a new access token.'''

    if not 'session_handle' in oaAccToken.__dict__:
        raise CascadeError(
            'Cannot refresh access token without a session handle.'
        )

    return oauth_get_access_token(oaConsumer, oaAccToken)

################################################################################
# Unit tests
################################################################################

def _oauth_token_to_query_string(tok):
    '''Serialize an OAuth token to a query string. This string should be
       compatible with oauth.OAuthToken.from_string().'''

    data = {
        'oauth_token': tok.key,
        'oauth_token_secret': tok.secret,
    }

    if tok.callback_confirmed is not None:
        data['oauth_callback_confirmed'] = tok.callback_confirmed
    if 'verifier' in tok.__dict__:
        data['oauth_verifier'] = tok.verifier
    if 'expires_on' in tok.__dict__:
        data['xoauth_expires_on'] = tok.expires_on
    if 'session_handle' in tok.__dict__:
        data['oauth_session_handle'] = tok.session_handle
    if 'authorization_expires_on' in tok.__dict__:
        data['xoauth_authorization_expires_on'] = tok.authorization_expires_on
    if 'yahoo_guid' in tok.__dict__:
        data['xoauth_yahoo_guid'] = tok.yahoo_guid

    return urllib.urlencode(data)

def _oauth_token_from_query_string(s):
    '''De-serialize an OAuth token from a query string. The query string
       could be generated by __oauth_token_to_query_string(), or via
       oauth.OAuthToken.to_string().'''

    tok = oauth.OAuthToken.from_string(s)
    params = cgi.parse_qs(s, keep_blank_values = False)

    if 'oauth_verifier' in params:
        tok.verifier = params['oauth_verifier'][0]
    if 'xoauth_expires_on' in params:
        tok.expires_on = int(params['xoauth_expires_on'][0])
    if 'oauth_session_handle' in params:
        tok.session_handle = params['oauth_session_handle'][0]
    if 'xoauth_authorization_expires_on' in params:
        tok.authorization_expires_on = int(params['xoauth_authorization_expires_on'][0])
    if 'xoauth_yahoo_guid' in params:
        tok.yahoo_guid = params['xoauth_yahoo_guid'][0]

    return tok

def _write_unittest_settings(consumerKey, consumerSecret, accTok):
    '''Write a cascade_unittest_settings.py module in the currrent
       directory, based on the provided paramters.'''

    f = open('cascade_unittest_settings.py', 'w')
    f.write(
"""OAUTH_CONSUMER_KEY = '%s'
OAUTH_CONSUMER_SECRET = '%s'
OAUTH_ACCESS_TOKEN = '%s'
""" % \
        (
            consumerKey,
            consumerSecret,
            _oauth_token_to_query_string(accTok),
        )
    )
    f.close()

def _generate_unittest_settings():
    '''Generate a cascade_unittest_settings.py module in the current
       directory.'''

    print '>>> generating cascade_unittest_settings.py'

    sys.stdout.write('consumer key: ')
    consumerKey = sys.stdin.readline().strip()

    sys.stdout.write('consumer secret: ')
    consumerSecret = sys.stdin.readline().strip()

    sys.stdout.write('consumer callback URL: ')
    consumerCbUrl = sys.stdin.readline().strip()

    oaConsumer = oauth.OAuthConsumer(consumerKey, consumerSecret)

    reqTok, url = oauth_get_request_token(oaConsumer, consumerCbUrl)

    print '''>>> navigate to the following URL in your browser, then paste
in token callback URL that results'''
    print url

    sys.stdout.write('token callback URL: ')
    tokenCbUrl = sys.stdin.readline().strip()

    tokenCbUrlQp = urlparse.urlsplit(tokenCbUrl).query
    tokenCbUrlDict = cgi.parse_qs(tokenCbUrlQp)

    assert(tokenCbUrlDict['oauth_token'][0] == reqTok.key)
    reqTok.set_verifier(tokenCbUrlDict['oauth_verifier'][0])

    accTok = oauth_get_access_token(oaConsumer, reqTok)

    _write_unittest_settings(consumerKey, consumerSecret, accTok)

class OAuthBaseTest(unittest.TestCase):
    '''Base class for tests, loading OAuth credentials.'''

    def setUp(self):
        # Create OAuth objects (a consumer, a request token, and access
        # token if requested) from unittest settings.
        self._oaConsumer = oauth.OAuthConsumer(
            cascade_unittest_settings.OAUTH_CONSUMER_KEY,
            cascade_unittest_settings.OAUTH_CONSUMER_SECRET
        )

        self._oaAccessToken = _oauth_token_from_query_string(cascade_unittest_settings.OAUTH_ACCESS_TOKEN)

class OAuthTest(OAuthBaseTest):
    '''Verify that OAuth access works at all.'''

    def testBadRequestToken(self):
        '''Verify that attempting to use a broken request token fails with a 401 HTTP status.'''

        oaBadRequestToken = oauth.OAuthToken('qqqq', 'vvvvv')
        oaBadRequestToken.set_verifier('zipf')

        try:
            oauth_get_access_token(self._oaConsumer, oaBadRequestToken)
        except CascadeHTTPError, e:
            self.assertEquals(401, e.getHTTPStatus())

class JSON11ClientTest(OAuthBaseTest):
    '''Verify that JSON11Client functions as expected.'''

    def setUp(self):
        OAuthBaseTest.setUp(self)

        self.__client = JSON11Client(self._oaConsumer, self._oaAccessToken)

    def tearDown(self):
        # If our client has refreshed the access token, update the unittest
        # settings module, both in-memory and on-disk.
        if cascade_unittest_settings.OAUTH_ACCESS_TOKEN != \
            _oauth_token_to_query_string(self.__client.getToken()):
            cascade_unittest_settings.OAUTH_ACCESS_TOKEN = _oauth_token_to_query_string(self.__client.getToken())
            _write_unittest_settings(
                cascade_unittest_settings.OAUTH_CONSUMER_KEY,
                cascade_unittest_settings.OAUTH_CONSUMER_SECRET,
                self.__client.getToken()
            )

    def testBasicRequest(self):
        '''Verify that a simple Cascade request works as expected.'''

        self.__client.call('ListFolders', [{}])

    def testHTTPError(self):
        '''Verify that a 500 HTTP results in a raised CascadeHTTPError with appropriate details filled in.'''

        try:
            # We happen to know that calling an undefined method results
            # in a 500 status.
            self.__client.call('ListFolders2', [{}])
            self.fail('Expected CascadeHTTPError with status 500.')
        except CascadeHTTPError, e:
            self.assertEquals(500, e.getHTTPStatus())

if __name__ == '__main__':
    # Load up unittest settings, creating them if non-existant. These
    # are stashed in cascade_unittest_settings.py and are loaded using
    # the standard module path.
    try:
        import cascade_unittest_settings
    except ImportError:
        _generate_unittest_settings()

        try:
            import cascade_unittest_settings
        except ImportError:
            print sys.stderr, '>>> unable to configure settings; exiting'
            sys.exit(1)

    unittest.main()
