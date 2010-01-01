# A Python library for talking Cascade.

import cgi
import oauth
import simplejson
import sys
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

class CascadeJSONError(CascadeError):
    '''An exception class for Cascade JSON errors. Wraps the 'error'
       element in JSON responses.'''

    def __init__(self, error):
        self.__error = error

    def getJSONError(self):
        '''Get the JSON error structure that came with this response.'''

        return self.__error

class CascadeHTTPError(CascadeError):
    '''An exception class for Cascade HTTP errors. Represents any non-200
       response that comes back from the Cascade server.'''

    def __init__(self, httpError):
        self.__httpError = httpError

    def __str__(self):
        return '%s: %d' % (self.__httpError.filename, self.__httpError.code)

    def getHTTPStatus(self):
        return self.__httpError.code

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

    def call(self, method = '', params = [{}]):
        '''Call the given method using the specified parameters (which are
           passed directly as the 'params' value in the JSON payload).
           Returns a result object derived from un-serializing the response
           JSON data. Raises a CascadeError if problems arise.'''

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
            raise CascadeHTTPError(e)
        finally:
            if cascadeResp:
                cascadeResp.close()

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
    '''Get an OAuth access token from the given request token. Returns an
       oauth.OAuthToken.'''

    assert(oaReqToken.verifier)

    oaSig = oauth.OAuthSignatureMethod_HMAC_SHA1()

    oaReq = oauth.OAuthRequest(
        http_method = 'GET',
        http_url = OAUTH2_ENDPOINT_URL + '/get_token',
        parameters = {
            'oauth_nonce' : oauth.generate_nonce(),
            'oauth_timestamp' : oauth.generate_timestamp(),
            'oauth_consumer_key' : oaConsumer.key,
            'oauth_verifier' : oaReqToken.verifier,
            'oauth_token' : oaReqToken.key,
            'oauth_version' : '1.0',
        }
    )

    oaReq.sign_request(oaSig, oaConsumer, oaReqToken)

    accTokenResp = None
    try:
        accTokenResp = urllib2.urlopen(oaReq.to_url())
        accTokenRespContent = ''.join(accTokenResp.readlines())

        return oauth.OAuthToken.from_string(accTokenRespContent)
    except urllib2.HTTPError, e:
        raise CascadeHTTPError(e)
    finally:
        if accTokenResp:
            accTokenResp.close()

def oauth_refresh_access_token(oaConsumer, oaAccToken):
    '''Refresh the given OAuth access token. Returns a new access token.'''

    return oauth_get_access_token(oaConsumer, oaAccToken)

################################################################################
# Unit tests
################################################################################

def generate_unittest_settings():
    '''Generate a cascade_unittest_settings.py module in the current
       directory.'''

    print '>>> generating cascade_unittest_settings.py'

    sys.stdout.write('consumer key: ')
    consumerKey = sys.stdin.readline().strip()

    sys.stdout.write('consumer secret: ')
    consumerSecret = sys.stdin.readline().strip()

    sys.stdout.write('application url: ')
    appUrl = sys.stdin.readline().strip()

    oaConsumer = oauth.OAuthConsumer(consumerKey, consumerSecret)

    reqTok, url = oauth_get_request_token(oaConsumer, appUrl)

    print '>>> nagivate to the following URL in your browser'
    print url

    sys.stdout.write('callback URL: ')
    cbUrl = sys.stdin.readline().strip()

    cbUrlQp = urlparse.urlsplit(cbUrl).query
    cbUrlDict = cgi.parse_qs(cbUrlQp)

    assert(cbUrlDict['oauth_token'][0] == reqTok.key)
    reqTok.set_verifier(cbUrlDict['oauth_verifier'][0])

    f = open('cascade_unittest_settings.py', 'w')
    f.write(
"""OAUTH_CONSUMER_KEY = '%s'
OAUTH_CONSUMER_SECRET = '%s'
OAUTH_REQUEST_TOKEN_JSON = '%s'
""" % (consumerKey, consumerSecret, simplejson.dumps({ 'key' : reqTok.key, 'secret' : reqTok.secret, 'verifier' : reqTok.verifier}))
    )
    f.close()

class OAuthBaseTest(unittest.TestCase):
    '''Base class for tests, loading OAuth credentials.'''

    _setupAccessToken = True

    def setUp(self):
        # Create OAuth objects (a consumer, a request token, and access
        # token if requested) from unittest settings.
        self._oaConsumer = oauth.OAuthConsumer(
            cascade_unittest_settings.OAUTH_CONSUMER_KEY,
            cascade_unittest_settings.OAUTH_CONSUMER_SECRET
        )

        reqTokJSON = simplejson.loads(cascade_unittest_settings.OAUTH_REQUEST_TOKEN_JSON)
        self._oaRequestToken = oauth.OAuthToken(
            reqTokJSON['key'],
            reqTokJSON['secret']
        )
        self._oaRequestToken.set_verifier(reqTokJSON['verifier'])

        if self._setupAccessToken:
            self._oaAccessToken = oauth_get_access_token(
                self._oaConsumer,
                self._oaRequestToken
            )

class OAuthTest(OAuthBaseTest):
    '''Verify that OAuth access works at all.'''

    def testBadRequestToken(self):
        '''Verify that attempting to use a broken request token fails
           with a 401 HTTP status.'''

        oaBadRequestToken = oauth.OAuthToken('qqqq', 'vvvvv')
        oaBadRequestToken.set_verifier('zipf')

        try:
            oauth_get_access_token(self._oaConsumer, oaBadRequestToken)
        except CascadeHTTPError, e:
            self.assertEquals(401, e.getHTTPStatus())

    def testAccessToken(self):
        '''Verify that we can acquire and use an access token from our
           request token.'''

        accTok = oauth_get_access_token(
            self._oaConsumer,
            self._oaRequestToken
        )

        self.assert_(accTok)

        jc = JSON11Client(self._oaConsumer, accTok)
        result = jc.call('ListFolders', [{}])

        self.assert_(result)

class JSON11ClientTest(OAuthBaseTest):
    '''Verify that JSON11Client functions as expected.'''

    _setupAccessToken = True

    def setUp(self):
        OAuthBaseTest.setUp(self)

        self.__client = JSON11Client(self._oaConsumer, self._oaAccessToken)

    def testHTTPError(self):
        '''Verify that a 500 HTTP results in a raised CascadeHTTPError with
           appropriate details filled in.'''

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
        generate_unittest_settings()

        try:
            import cascade_unittest_settings
        except ImportError:
            print sys.stderr, '>>> unable to configure settings; exiting'
            sys.exit(1)

    unittest.main()
