# Yggdrasil Authentication Server

A Django-based implementation of the Yggdrasil authentication protocol for Minecraft servers.

## Project Structure

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

## Features

- **Authentication**: Full Yggdrasil protocol implementation
- **Security**: RSA-signed JWT tokens with 24-hour expiration
- **Validation**: Comprehensive input sanitization and validation
- **Testing**: Automated test suite covering all endpoints
- **Modular Design**: Clean separation of concerns by functionality
- **Username Validation**: Minecraft-compliant username rules (a-z, A-Z, 0-9, -, _)

## Endpoints

### Authentication (`/yggdrasil/auth/`)
- `POST /authenticate/` - User authentication
- `POST /refresh/` - Token refresh
- `POST /validate/` - Token validation
- `POST /signout/` - User signout
- `POST /invalidate/` - Token invalidation

### Account (`/yggdrasil/account/`)
- `GET /profile/` - Get user profile
- `GET /profiles/` - Get multiple profiles

### Session (`/yggdrasil/session/`)
- `GET /join/` - Handle server join
- `GET /hasJoined/` - Check if user has joined

### Services (`/yggdrasil/services/`)
- `GET /` - Services overview

## Security Features

- RSA-512 signed JWT tokens
- Input validation and sanitization
- Token expiration (24 hours)
- Client token validation
- Protection against common attacks
- Username format validation (Minecraft rules)

## Installation

```bash
# Install dependencies
pip install -r requirements.txt
# or
pip install -r req.txt

# Run tests
python yggdrasil/tests.py

# Start development server
python manage.py runserver
```

## Testing

The server includes comprehensive tests for all endpoints:

```bash
# Run all tests
python yggdrasil/tests.py

# Test specific endpoints manually
curl -X POST http://127.0.0.1:8000/yggdrasil/auth/authenticate/ \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "testpass", "clientToken": "test123"}'
```

## Production Considerations

- Replace hardcoded credentials with database
- Implement rate limiting
- Add HTTPS
- Configure proper logging
- Use production WSGI server
- Add CORS policies
- Implement proper user management
- Add password hashing
- Configure token storage in database
