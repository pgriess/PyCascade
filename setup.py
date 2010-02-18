from distutils.core import setup

setup(
    name = 'PyCascade',
    version = '1.0',
    author = 'Peter Griess',
    author_email = 'pgriess@gmail.com',
    maintainer = 'Peter Griess',
    maintainer_email = 'pgriess@gmail.com',
    url = 'http://github.com/pgriess/PyCascade',
    download_url = 'http://github.com/downloads/pgriess/PyCascade/PyCascade-1.0.tar.gz',
    description = 'A Python client for Cascade, the Yahoo! Mail API',
    long_description = 'A Python implementation of a `Cascade <http://developer.yahoo.com/mail/>`_ client; uses `OAuth <http://developer.yahoo.com/oauth/>`_ for authorization.',
    classifiers = [
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python',
        'Topic :: Communications :: Email',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    py_modules = ['cascade'],
    requires = ['oauth'],
    provides = ['cascade']
)
