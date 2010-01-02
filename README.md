# Background

PyCascade is a Python [Cascade](http://developer.yahoo.com/mail/) client
implementation, written in pure Python. Although Cascade supports both BBAuth
and OAuth authorization models, PyCascade supports only OAuth, via the
[oauth](http://code.google.com/p/oauth/) library. Only the JSON variant of the
API is currently supported.

To apply for an OAuth key that works with Cascade, check out the [YDN OAuth
documentation](http://developer.yahoo.com/oauth/).

# Testing

PyCascade sports a handful of unit tests, which are executed by invoking
`cascade.py` directly from the shell, as follows:

    % python ./cascade.py
    ..
    ----------------------------------------------------------------------
    Ran 2 tests in 1.005s

    OK

## OAuth Configuration

Most of these unit tests require OAuth authentication. As we do not want to
commit these credentials to source control, a facility exists to generate
them by interviewing the invoker, and persisting the results in the
`cascade_unittest_settings.py` module in the current working directory.  The
_consumer callback URL_ should have the same hostname as the one configured
with the OAuth key being used, but should result in a 404. The idea is that
we do not want the OAuth authorization flow to end up somewhere "real" -- we
just want to steal the query parameters that are generated as part of this
flow. Thus, the _token callback URL_ is just the _consumer callback URL_ with
some query parameters populated by the OAuth flow.

In the following example, `http://www.yttrium.ws` is configured as the
application URL for our OAuth key. We synthesize a fictitious path with some
gook to ensure a 404.

    % rm -f cascade_unittest_settings.py*
    % python ./cascade.py
    >>> generating cascade_unittest_settings.py
    consumer key: 6epbh1bl4p2zdnhsn5bnikcu2n73apewat0hp166dzkit8n84pe6fjvruagjg3r3wh824cnp45av5pueag274xzayzb2awipnvci
    consumer secret: x4jhpriqzwbaojwhkq2hhrkm2nagmuyd7yqawjmc
    consumer callback URL: http://www.yttrium.ws/qqzzbb
    >>> navigate to the following URL in your browser, then paste in the tokenc allback URL that results
    https://api.login.yahoo.com/oauth/v2/request_auth?oauth_token=crw2ke7
    token callback URL: http://www.yttrium.ws/qqzzbb?oauth_token=crw2ke7&oauth_verifier=o3caph
    ..
    ----------------------------------------------------------------------
    Ran 2 tests in 1.005s

    OK

## Using an HTTP Proxy

The unit tests can be run using an HTTP proxy by utilizing the built-in support
that `urllib2` provides for proxies. In the following example, both HTTP and
HTTPS are sent through a proxy running on `localhost` port 8888.

    % export http_proxy='http://localhost:8888'
    % export https_prpxy='http://localhost:8888'
    % python ./cascade.py
    ...
