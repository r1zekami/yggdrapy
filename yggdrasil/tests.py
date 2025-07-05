"""
Automated tests for Yggdrasil API
"""
import json
import time
from django.test import TestCase, Client
from django.urls import reverse
from unittest.mock import patch
import jwt


class YggdrasilAuthTestCase(TestCase):
    """Tests for authentication endpoints"""
    
    def setUp(self):
        """Setup before each test"""
        self.client = Client()
        self.authenticate_url = '/yggdrasil/auth/authenticate'
        self.refresh_url = '/yggdrasil/auth/refresh'
        self.validate_url = '/yggdrasil/auth/validate'
        self.signout_url = '/yggdrasil/auth/signout'
        self.invalidate_url = '/yggdrasil/auth/invalidate'
        
        # Test data
        self.valid_credentials = {
            'username': 'testuser',
            'password': 'testpass',
            'clientToken': 'test-client-token'
        }
        
        self.invalid_credentials = {
            'username': 'wronguser',
            'password': 'wrongpass',
            'clientToken': 'test-client-token'
        }

    def test_authenticate_success(self):
        """Test successful authentication"""
        response = self.client.post(
            self.authenticate_url,
            data=json.dumps(self.valid_credentials),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        
        # Check response structure
        self.assertIn('accessToken', data)
        self.assertIn('clientToken', data)
        self.assertIn('availableProfiles', data)
        self.assertIn('selectedProfile', data)
        # 'user' field may be missing in some implementations
        
        # Check that token is valid JWT
        token = data['accessToken']
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            self.assertIn('exp', payload)
            self.assertIn('iat', payload)
            self.assertIn('sub', payload)
            self.assertIn('clientToken', payload)
        except jwt.InvalidTokenError:
            self.fail("Generated token is not a valid JWT")

    def test_authenticate_invalid_credentials(self):
        """Test authentication with invalid credentials"""
        response = self.client.post(
            self.authenticate_url,
            data=json.dumps(self.invalid_credentials),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 403)
        data = json.loads(response.content)
        self.assertIn('error', data)
        self.assertIn('errorMessage', data)

    def test_authenticate_missing_fields(self):
        """Test authentication with missing fields"""
        incomplete_data = {'username': 'testuser'}
        
        response = self.client.post(
            self.authenticate_url,
            data=json.dumps(incomplete_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)

    def test_authenticate_invalid_json(self):
        """Test authentication with invalid JSON"""
        response = self.client.post(
            self.authenticate_url,
            data='invalid json',
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)

    def test_authenticate_username_validation(self):
        """Test username validation"""
        invalid_usernames = [
            'user@domain.com',  # contains @
            'user name',        # contains space
            'user.name',        # contains dot
            'a' * 17,           # too long
            '',                 # empty
            'user123!',         # contains special characters
        ]
        valid_but_wrong_usernames = [
            'notexist',        # valid format but non-existent
            'testuser1',       # valid format but non-existent
        ]
        # Check invalid usernames
        for username in invalid_usernames:
            test_data = {
                'username': username,
                'password': 'testpass',
                'clientToken': 'test-client-token'
            }
            response = self.client.post(
                self.authenticate_url,
                data=json.dumps(test_data),
                content_type='application/json'
            )
            self.assertEqual(response.status_code, 403)
            data = json.loads(response.content)
            self.assertEqual(data['error'], 'ForbiddenOperationException')
            self.assertEqual(data['errorMessage'], 'Forbidden')
        # Check valid but non-existent usernames
        for username in valid_but_wrong_usernames:
            test_data = {
                'username': username,
                'password': 'testpass',
                'clientToken': 'test-client-token'
            }
            response = self.client.post(
                self.authenticate_url,
                data=json.dumps(test_data),
                content_type='application/json'
            )
            self.assertEqual(response.status_code, 403)
            data = json.loads(response.content)
            self.assertEqual(data['error'], 'ForbiddenOperationException')
            self.assertEqual(data['errorMessage'], 'Invalid credentials. Invalid username or password.')

    def test_authenticate_password_validation(self):
        """Test password validation"""
        invalid_passwords = [
            '',                 # empty
            'a' * 101,          # too long
            'pass\nword',       # contains newline
            'pass\tword',       # contains tab
        ]
        
        for password in invalid_passwords:
            test_data = {
                'username': 'testuser',
                'password': password,
                'clientToken': 'test-client-token'
            }
            
            response = self.client.post(
                self.authenticate_url,
                data=json.dumps(test_data),
                content_type='application/json'
            )
            
            self.assertEqual(response.status_code, 403)
            data = json.loads(response.content)
            self.assertEqual(data['error'], 'ForbiddenOperationException')
            # For invalid passwords, it can be either 'Forbidden' or 'Invalid credentials'
            self.assertIn(data['errorMessage'], ['Forbidden', 'Invalid credentials. Invalid username or password.'])

    def test_refresh_success(self):
        """Test successful token refresh"""
        # First get token
        auth_response = self.client.post(
            self.authenticate_url,
            data=json.dumps(self.valid_credentials),
            content_type='application/json'
        )
        auth_data = json.loads(auth_response.content)
        
        # Refresh token
        refresh_data = {
            'accessToken': auth_data['accessToken'],
            'clientToken': auth_data['clientToken']
        }
        
        response = self.client.post(
            self.refresh_url,
            data=json.dumps(refresh_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        
        # Check that we got a new token
        self.assertIn('accessToken', data)
        self.assertIn('clientToken', data)
        self.assertNotEqual(data['accessToken'], auth_data['accessToken'])

    def test_refresh_invalid_token(self):
        """Test refresh with invalid token"""
        refresh_data = {
            'accessToken': 'invalid.token.here',
            'clientToken': 'test-client-token'
        }
        
        response = self.client.post(
            self.refresh_url,
            data=json.dumps(refresh_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 403)

    def test_refresh_mismatched_client_token(self):
        """Test refresh with wrong clientToken"""
        # Get token
        auth_response = self.client.post(
            self.authenticate_url,
            data=json.dumps(self.valid_credentials),
            content_type='application/json'
        )
        auth_data = json.loads(auth_response.content)
        
        # Try to refresh with wrong clientToken
        refresh_data = {
            'accessToken': auth_data['accessToken'],
            'clientToken': 'wrong-client-token'
        }
        
        response = self.client.post(
            self.refresh_url,
            data=json.dumps(refresh_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 403)

    def test_validate_success(self):
        """Test successful token validation"""
        # Get token
        auth_response = self.client.post(
            self.authenticate_url,
            data=json.dumps(self.valid_credentials),
            content_type='application/json'
        )
        auth_data = json.loads(auth_response.content)
        
        # Validate token
        validate_data = {
            'accessToken': auth_data['accessToken']
        }
        
        response = self.client.post(
            self.validate_url,
            data=json.dumps(validate_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 204)

    def test_validate_with_client_token(self):
        """Test validation with clientToken"""
        # Get token
        auth_response = self.client.post(
            self.authenticate_url,
            data=json.dumps(self.valid_credentials),
            content_type='application/json'
        )
        auth_data = json.loads(auth_response.content)
        
        # Validate token with clientToken
        validate_data = {
            'accessToken': auth_data['accessToken'],
            'clientToken': auth_data['clientToken']
        }
        
        response = self.client.post(
            self.validate_url,
            data=json.dumps(validate_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 204)

    def test_validate_invalid_token(self):
        """Test validation of invalid token"""
        validate_data = {
            'accessToken': 'invalid.token.here'
        }
        
        response = self.client.post(
            self.validate_url,
            data=json.dumps(validate_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 403)

    def test_signout_success(self):
        """Test successful signout"""
        signout_data = {
            'username': 'testuser',
            'password': 'testpass'
        }
        
        response = self.client.post(
            self.signout_url,
            data=json.dumps(signout_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'')

    def test_signout_invalid_credentials(self):
        """Test signout with invalid credentials"""
        signout_data = {
            'username': 'testuser',
            'password': 'wrongpass'
        }
        
        response = self.client.post(
            self.signout_url,
            data=json.dumps(signout_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 403)

    def test_invalidate_success(self):
        """Test successful token invalidation"""
        # Get token
        auth_response = self.client.post(
            self.authenticate_url,
            data=json.dumps(self.valid_credentials),
            content_type='application/json'
        )
        auth_data = json.loads(auth_response.content)
        
        # Invalidate token
        invalidate_data = {
            'accessToken': auth_data['accessToken'],
            'clientToken': auth_data['clientToken']
        }
        
        response = self.client.post(
            self.invalidate_url,
            data=json.dumps(invalidate_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'')
        
        # Check that token is actually invalidated
        validate_data = {
            'accessToken': auth_data['accessToken']
        }
        
        validate_response = self.client.post(
            self.validate_url,
            data=json.dumps(validate_data),
            content_type='application/json'
        )
        
        self.assertEqual(validate_response.status_code, 403)

    def test_invalidate_mismatched_client_token(self):
        """Test invalidation with wrong clientToken"""
        # Get token
        auth_response = self.client.post(
            self.authenticate_url,
            data=json.dumps(self.valid_credentials),
            content_type='application/json'
        )
        auth_data = json.loads(auth_response.content)
        
        # Try to invalidate with wrong clientToken
        invalidate_data = {
            'accessToken': auth_data['accessToken'],
            'clientToken': 'wrong-client-token'
        }
        
        response = self.client.post(
            self.invalidate_url,
            data=json.dumps(invalidate_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 403)

    def test_token_expiry(self):
        """Test token expiration"""
        # Get token
        auth_response = self.client.post(
            self.authenticate_url,
            data=json.dumps(self.valid_credentials),
            content_type='application/json'
        )
        auth_data = json.loads(auth_response.content)
        
        # Check expiration time in token
        token = auth_data['accessToken']
        payload = jwt.decode(token, options={"verify_signature": False})
        
        current_time = int(time.time())
        expiry_time = payload['exp']
        time_until_expiry = expiry_time - current_time
        
        # Token should expire in ~24 hours
        self.assertGreater(time_until_expiry, 0)
        self.assertGreater(time_until_expiry, 86300)  # More than 23:59:00
        self.assertLess(time_until_expiry, 86410)     # Less than 24:00:10

    def test_concurrent_requests(self):
        """Test concurrent requests"""
        import threading
        import queue
        
        results = queue.Queue()
        
        def make_request():
            try:
                response = self.client.post(
                    self.authenticate_url,
                    data=json.dumps(self.valid_credentials),
                    content_type='application/json'
                )
                results.put(response.status_code)
            except Exception as e:
                results.put(f"Error: {e}")
        
        # Start 5 concurrent requests
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Check results
        while not results.empty():
            result = results.get()
            self.assertEqual(result, 200)

    def test_malicious_inputs(self):
        """Test malicious input handling"""
        malicious_inputs = [
            # SQL injection
            {'username': "'; DROP TABLE users; --", 'password': 'testpass'},
            # XSS
            {'username': '<script>alert("xss")</script>', 'password': 'testpass'},
            # Very long inputs
            {'username': 'a' * 1000, 'password': 'b' * 1000},
            # Null bytes
            {'username': 'user\x00name', 'password': 'testpass'},
            # Unicode injection
            {'username': 'user\u0000name', 'password': 'testpass'},
        ]
        
        for malicious_input in malicious_inputs:
            response = self.client.post(
                self.authenticate_url,
                data=json.dumps(malicious_input),
                content_type='application/json'
            )
            
            # Should get 403 or 400, but not 500
            self.assertIn(response.status_code, [400, 403])


class YggdrasilURLTestCase(TestCase):
    """Tests for URL routes"""
    
    def test_auth_urls(self):
        """Test URL endpoint availability"""
        urls = [
            '/yggdrasil/auth/authenticate',
            '/yggdrasil/auth/refresh',
            '/yggdrasil/auth/validate',
            '/yggdrasil/auth/signout',
            '/yggdrasil/auth/invalidate',
        ]
        
        for url in urls:
            response = self.client.get(url)
            # GET requests should return 405 Method Not Allowed
            self.assertEqual(response.status_code, 405)
            
            # POST requests with empty body should return 400
            response = self.client.post(url, content_type='application/json')
            self.assertEqual(response.status_code, 400)

    def test_main_pages(self):
        """Test main pages"""
        urls = [
            '/yggdrasil/',
            '/yggdrasil/account/',
            '/yggdrasil/session/',
            '/yggdrasil/services/',
        ]
        
        for url in urls:
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)
            self.assertContains(response, 'Yggdrasil')


class YggdrasilIntegrationTestCase(TestCase):
    """Integration tests for full cycle"""
    
    def setUp(self):
        self.client = Client()
        self.credentials = {
            'username': 'testuser',
            'password': 'testpass',
            'clientToken': 'integration-test-token'
        }

    def test_full_auth_cycle(self):
        """Test full authentication cycle"""
        # 1. Authentication
        auth_response = self.client.post(
            '/yggdrasil/auth/authenticate',
            data=json.dumps(self.credentials),
            content_type='application/json'
        )
        self.assertEqual(auth_response.status_code, 200)
        auth_data = json.loads(auth_response.content)
        
        # 2. Token validation
        validate_response = self.client.post(
            '/yggdrasil/auth/validate',
            data=json.dumps({'accessToken': auth_data['accessToken']}),
            content_type='application/json'
        )
        self.assertEqual(validate_response.status_code, 204)
        
        # 3. Token refresh
        refresh_response = self.client.post(
            '/yggdrasil/auth/refresh',
            data=json.dumps({
                'accessToken': auth_data['accessToken'],
                'clientToken': auth_data['clientToken']
            }),
            content_type='application/json'
        )
        self.assertEqual(refresh_response.status_code, 200)
        refresh_data = json.loads(refresh_response.content)
        
        # 4. Validate new token
        validate_response = self.client.post(
            '/yggdrasil/auth/validate',
            data=json.dumps({'accessToken': refresh_data['accessToken']}),
            content_type='application/json'
        )
        self.assertEqual(validate_response.status_code, 204)
        
        # 5. Invalidate token
        invalidate_response = self.client.post(
            '/yggdrasil/auth/invalidate',
            data=json.dumps({
                'accessToken': refresh_data['accessToken'],
                'clientToken': refresh_data['clientToken']
            }),
            content_type='application/json'
        )
        self.assertEqual(invalidate_response.status_code, 200)
        
        # 6. Check that token is invalidated
        validate_response = self.client.post(
            '/yggdrasil/auth/validate',
            data=json.dumps({'accessToken': refresh_data['accessToken']}),
            content_type='application/json'
        )
        self.assertEqual(validate_response.status_code, 403)
        
        # 7. Signout
        signout_response = self.client.post(
            '/yggdrasil/auth/signout',
            data=json.dumps({
                'username': self.credentials['username'],
                'password': self.credentials['password']
            }),
            content_type='application/json'
        )
        self.assertEqual(signout_response.status_code, 200)

    def test_token_reuse_after_invalidate(self):
        """Test reuse of invalidated token"""
        # Get token
        auth_response = self.client.post(
            '/yggdrasil/auth/authenticate',
            data=json.dumps(self.credentials),
            content_type='application/json'
        )
        auth_data = json.loads(auth_response.content)
        
        # Invalidate token
        self.client.post(
            '/yggdrasil/auth/invalidate',
            data=json.dumps({
                'accessToken': auth_data['accessToken'],
                'clientToken': auth_data['clientToken']
            }),
            content_type='application/json'
        )
        
        # Try to use invalidated token for refresh
        refresh_response = self.client.post(
            '/yggdrasil/auth/refresh',
            data=json.dumps({
                'accessToken': auth_data['accessToken'],
                'clientToken': auth_data['clientToken']
            }),
            content_type='application/json'
        )
        
        self.assertEqual(refresh_response.status_code, 403)
