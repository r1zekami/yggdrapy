import json
import time
from django.test import TestCase, Client
from django.urls import reverse
from unittest.mock import patch
import jwt
from django.contrib.auth.models import User
from accounts.models import Profile
import uuid


class YggdrasilAuthTestCase(TestCase):
    def setUp(self):
        self.valid_user_uuid = uuid.UUID("11111111-1111-1111-1111-111111111111")
        self.valid_profile_uuid = uuid.UUID("123e4567-e89b-12d3-a456-426614174000")
        self.invalid_profile_uuid = uuid.UUID("deadbeef-dead-beef-dead-beefdeadbeef")
        self.bad_format_uuid = "not-a-uuid"

        self.user = User.objects.create_user(username='testuser', password='testpass_123zxc')
        self.profile = Profile.objects.create(
            user=self.user,
            user_UUID=self.valid_user_uuid,
            profile_UUID=self.valid_profile_uuid,
            access_token=None,
            client_token=None
        )
        self.client = Client()
        self.authenticate_url = '/yggdrasil/auth/authenticate'
        self.refresh_url = '/yggdrasil/auth/refresh'
        self.validate_url = '/yggdrasil/auth/validate'
        self.signout_url = '/yggdrasil/auth/signout'
        self.invalidate_url = '/yggdrasil/auth/invalidate'
        
        self.valid_credentials = {
            'username': 'testuser',
            'password': 'testpass_123zxc',
            'clientToken': 'test-client-token',
            'profile_UUID': str(self.valid_profile_uuid),
        }
        
        self.invalid_credentials = {
            'username': 'wronguser',
            'password': 'wrongpass',
            'clientToken': 'test-client-token',
            'profile_UUID': str(self.invalid_profile_uuid),
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
            'user@domain.com',
            'user name',
            'user.name',
            'a' * 17,
            '',
            'user123!',
        ]
        valid_but_wrong_usernames = [
            'notexist',
            'testuser1',
        ]
        # Check invalid usernames
        for username in invalid_usernames:
            test_data = {
                'username': username,
                'password': 'testpass_123zxc',
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
                'password': 'testpass_123zxc',
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
            '',
            'a' * 101,
            'pass\nword',
            'pass\tword',
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
            self.assertIn(data['errorMessage'], ['Forbidden', 'Invalid credentials. Invalid username or password.'])

    def test_refresh_success(self):
        """Test successful token refresh"""
        auth_response = self.client.post(
            self.authenticate_url,
            data=json.dumps(self.valid_credentials),
            content_type='application/json'
        )
        auth_data = json.loads(auth_response.content)
        
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
            'password': 'testpass_123zxc'
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
            {'username': "'; DROP TABLE users; --", 'password': 'testpass_123zxc'},
            # XSS
            {'username': '<script>alert("xss")</script>', 'password': 'testpass_123zxc'},
            # Very long inputs
            {'username': 'a' * 1000, 'password': 'b' * 1000},
            # Null bytes
            {'username': 'user\x00name', 'password': 'testpass_123zxc'},
            # Unicode injection
            {'username': 'user\u0000name', 'password': 'testpass_123zxc'},
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

    def test_publickeys_endpoint(self):
        """Test publickeys endpoint"""
        response = self.client.get('/yggdrasil/services/publickeys')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.content)
        self.assertIn('profilePropertyKeys', data)
        self.assertIn('playerCertificateKeys', data)
        
        # Check profilePropertyKeys format
        self.assertIsInstance(data['profilePropertyKeys'], list)
        self.assertGreater(len(data['profilePropertyKeys']), 0)
        self.assertIn('publicKey', data['profilePropertyKeys'][0])
        
        # Check playerCertificateKeys format
        self.assertIsInstance(data['playerCertificateKeys'], list)
        self.assertGreater(len(data['playerCertificateKeys']), 0)
        self.assertIn('publicKey', data['playerCertificateKeys'][0])
        
        # Check that it's a valid Base64 public key
        public_key = data['profilePropertyKeys'][0]['publicKey']
        # Should be Base64 encoded (no PEM headers)
        self.assertNotIn('-----BEGIN PUBLIC KEY-----', public_key)
        self.assertNotIn('-----END PUBLIC KEY-----', public_key)
        # Should be valid Base64
        import base64
        try:
            base64.b64decode(public_key)
        except Exception:
            self.fail("Public key is not valid Base64")


class YggdrasilIntegrationTestCase(TestCase):
    """Integration tests for full cycle"""
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpass_123zxc')
        self.profile = Profile.objects.create(user=self.user)
        self.client = Client()
        self.credentials = {
            'username': 'testuser',
            'password': 'testpass_123zxc',
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


class YggdrasilSessionTestCase(TestCase):
    """Test cases for session management endpoints"""
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpass_123zxc')
        self.profile = Profile.objects.create(user=self.user)
        self.join_url = '/yggdrasil/session/join'
        self.has_joined_url = '/yggdrasil/session/hasJoined'
        # Valid credentials for authentication
        self.valid_credentials = {
            'username': 'testuser',
            'password': 'testpass_123zxc',
            'clientToken': 'test-client-token'
        }
        # Valid session join data
        self.valid_join_data = {
            'accessToken': '',  # Will be filled after authentication
            'selectedProfile': {
                'id': str(self.profile.profile_UUID),
                'name': 'testuser'
            },
            'serverId': 'test-server-hash-12345'
        }

    def test_join_success(self):
        """Test successful server join"""
        # First authenticate to get access token
        auth_response = self.client.post(
            '/yggdrasil/auth/authenticate',
            data=json.dumps(self.valid_credentials),
            content_type='application/json'
        )
        self.assertEqual(auth_response.status_code, 200)
        auth_data = json.loads(auth_response.content)
        
        # Use the access token for join request
        join_data = self.valid_join_data.copy()
        join_data['accessToken'] = auth_data['accessToken']
        
        response = self.client.post(
            self.join_url,
            data=json.dumps(join_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 204)

    def test_join_missing_access_token(self):
        """Test join request without access token"""
        join_data = self.valid_join_data.copy()
        del join_data['accessToken']
        
        response = self.client.post(
            self.join_url,
            data=json.dumps(join_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertEqual(data['error'], 'Missing accessToken')

    def test_join_missing_server_id(self):
        """Test join request without server ID"""
        # First authenticate to get access token
        auth_response = self.client.post(
            '/yggdrasil/auth/authenticate',
            data=json.dumps(self.valid_credentials),
            content_type='application/json'
        )
        self.assertEqual(auth_response.status_code, 200)
        auth_data = json.loads(auth_response.content)
        
        # Create join data with valid token but missing serverId
        join_data = {
            'accessToken': auth_data['accessToken'],
            'selectedProfile': {
                'id': '550e8400e29b41d4a716446655440000',
                'name': 'testuser'
            }
            # serverId is missing
        }
        
        response = self.client.post(
            self.join_url,
            data=json.dumps(join_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertEqual(data['error'], 'Missing serverId')

    def test_join_invalid_access_token(self):
        """Test join request with invalid access token"""
        join_data = self.valid_join_data.copy()
        join_data['accessToken'] = 'invalid.token.here'
        
        response = self.client.post(
            self.join_url,
            data=json.dumps(join_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 403)
        data = json.loads(response.content)
        self.assertEqual(data['error'], 'ForbiddenOperationException')

    def test_join_invalid_json(self):
        """Test join request with invalid JSON"""
        response = self.client.post(
            self.join_url,
            data='invalid json',
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertEqual(data['error'], 'Invalid JSON')

    def test_has_joined_success(self):
        """Test successful hasJoined check"""
        # First authenticate and join server
        auth_response = self.client.post(
            '/yggdrasil/auth/authenticate',
            data=json.dumps(self.valid_credentials),
            content_type='application/json'
        )
        auth_data = json.loads(auth_response.content)
        
        join_data = self.valid_join_data.copy()
        join_data['accessToken'] = auth_data['accessToken']
        
        join_response = self.client.post(
            self.join_url,
            data=json.dumps(join_data),
            content_type='application/json'
        )
        self.assertEqual(join_response.status_code, 204)
        
        # Now check hasJoined
        response = self.client.get(
            f'{self.has_joined_url}?username=testuser&serverId=test-server-hash-12345'
        )
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn('id', data)
        self.assertIn('name', data)
        self.assertIn('properties', data)
        self.assertEqual(data['name'], 'testuser')

    def test_has_joined_not_found(self):
        """Test hasJoined when user hasn't joined"""
        response = self.client.get(
            f'{self.has_joined_url}?username=testuser&serverId=nonexistent-server'
        )
        
        self.assertEqual(response.status_code, 204)

    def test_has_joined_missing_username(self):
        """Test hasJoined without username parameter"""
        response = self.client.get(
            f'{self.has_joined_url}?serverId=test-server-hash-12345'
        )
        
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertEqual(data['error'], 'Missing username parameter')

    def test_has_joined_missing_server_id(self):
        """Test hasJoined without serverId parameter"""
        response = self.client.get(
            f'{self.has_joined_url}?username=testuser'
        )
        
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertEqual(data['error'], 'Missing serverId parameter')

    def test_minecraft_profile_success(self):
        """Test successful minecraft profile request"""
        response = self.client.get(
            '/yggdrasil/session/minecraft/profile/550e8400e29b41d4a716446655440000'
        )
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        
        self.assertIn('id', data)
        self.assertIn('name', data)
        self.assertIn('properties', data)
        self.assertEqual(data['id'], '550e8400e29b41d4a716446655440000')
        self.assertEqual(data['name'], 'testuser')
        
        # Check properties
        self.assertIsInstance(data['properties'], list)
        self.assertGreater(len(data['properties']), 0)
        
        texture_property = data['properties'][0]
        self.assertEqual(texture_property['name'], 'textures')
        self.assertIn('value', texture_property)
        
        # Check that value is valid Base64
        import base64
        try:
            decoded = base64.b64decode(texture_property['value'])
            texture_data = json.loads(decoded.decode('utf-8'))
            self.assertIn('timestamp', texture_data)
            self.assertIn('profileId', texture_data)
            self.assertIn('profileName', texture_data)
            self.assertIn('textures', texture_data)
        except Exception:
            self.fail("Texture value is not valid Base64 JSON")

    def test_minecraft_profile_not_found(self):
        """Test minecraft profile request for non-existent profile"""
        response = self.client.get(
            '/yggdrasil/session/minecraft/profile/nonexistent-profile-id'
        )
        
        self.assertEqual(response.status_code, 404)
        data = json.loads(response.content)
        self.assertEqual(data['error'], 'Profile not found')

    def test_minecraft_profile_unsigned_true(self):
        """Test minecraft profile request with unsigned=true"""
        response = self.client.get(
            '/yggdrasil/session/minecraft/profile/550e8400e29b41d4a716446655440000?unsigned=true'
        )
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        
        # Should not have signature when unsigned=true
        texture_property = data['properties'][0]
        self.assertNotIn('signature', texture_property)

    def test_minecraft_profile_unsigned_false(self):
        """Test minecraft profile request with unsigned=false"""
        response = self.client.get(
            '/yggdrasil/session/minecraft/profile/550e8400e29b41d4a716446655440000?unsigned=false'
        )
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        
        # Should have signature when unsigned=false
        texture_property = data['properties'][0]
        self.assertIn('signature', texture_property)

