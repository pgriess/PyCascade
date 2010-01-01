# Background

PyCascade is a Python [Cascade](http://developer.yahoo.com/mail/) client
implementation, written in pure Python. Although Cascade supports both BBAuth
and OAuth authorizaiton models, PyCascade supports only OAuth, via the
[oauth](http://code.google.com/p/oauth/) library. Only the JSON variant of the
API is currently supported.

To apply for an OAuth key that works with Cascade, check out the [YDN OAuth
documentation](http://developer.yahoo.com/oauth/).

# Testing

PyCascade sports a number of unit tests, which are executed by invoking
`cascade.py` directly from the shell. As most of these tests require OAuth
authentication, a facility exists to read OAuth credentials from the
`cascade_unittest_settings` module. If this module does not exist, the user is
taken through OAuth handshaking on the console, and the file is created with
the result of this sequence.

The unit tests can be run using an HTTP proxy by utilizing the built-in support
that `urllib2` provides for proxies. In the following example, both HTTP and
HTTPS are sent through a proxy running on `localhost` port 8888.

    % env \
        http_proxy='http://localhost:8888' \
        https_prpxy='http://localhost:8888' \
        python ./cascade.py
