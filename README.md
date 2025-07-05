
```
yggdrasil/
├── auth/            # Authentication module
│   ├── __init__.py
│   ├── views.py     # authenticate, refresh, validate, signout, invalidate
│   └── urls.py      # Auth URL patterns
├── account/         # Account management module
│   ├── __init__.py
│   ├── views.py     # profile, profiles
│   └── urls.py      # Account URL patterns
├── session/         # Session management module
│   ├── __init__.py
│   ├── views.py     # join, hasJoined
│   └── urls.py      # Session URL patterns
├── services/        # Services module
│   ├── __init__.py
│   ├── views.py     # services
│   └── urls.py      # Services URL patterns
├── views.py         # Main views and landing pages
├── urls.py          # Main URL routing configuration
├── sanitize.py      # Input validation and sanitization
├── rsa_keys.py      # RSA key management for JWT signing
├── tests.py         # Automated tests
└── keys/            # RSA key storage
```
