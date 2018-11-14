"""Example Django settings for djopenid project."""
from __future__ import unicode_literals

import os
import sys
import warnings

try:
    import openid
except ImportError as e:
    warnings.warn("Could not import OpenID library.  Please consult the djopenid README.")
    sys.exit(1)
else:
    del openid

DEBUG = True
ALLOWED_HOSTS = ['*']

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',  # Add 'postgresql_psycopg2', 'mysql', 'sqlite3' or 'oracle'.
        'NAME': ':memory:',
    }
}

SECRET_KEY = 'u^bw6lmsa6fah0$^lz-ct$)y7x7#ag92-z+y45-8!(jk0lkavy'
SESSION_ENGINE = 'django.contrib.sessions.backends.file'
SESSION_SERIALIZER = 'django.contrib.sessions.serializers.PickleSerializer'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))],
        'APP_DIRS': True,
    }
]

MIDDLEWARE = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
)

ROOT_URLCONF = 'djopenid.urls'

INSTALLED_APPS = (
    'django.contrib.sessions',
    'djopenid.consumer',
    'djopenid.server',
)
