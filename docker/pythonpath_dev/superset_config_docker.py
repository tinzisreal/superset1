from flask_appbuilder.security.manager import AUTH_OAUTH
from superset.security import SupersetSecurityManager
import logging

SECRET_KEY = 'tungdeptrai'

# Enable OAuth authentication
AUTH_TYPE = AUTH_OAUTH
LOGOUT_REDIRECT_URL = 'http://localhost:8180/realms/master/protocol/openid-connect/logout'
AUTH_USER_REGISTRATION = True
AUTH_USER_REGISTRATION_ROLE = 'Gamma'

HTTP_HEADERS = {
    "X-Frame-Options": "ALLOWALL"
}
OAUTH_PROVIDERS = [
    {
        "name": "tung",   # tên provider, sẽ hiển thị nút "Login with kc"
        "icon": "fa-key",
        "token_key": "access_token",
        "remote_app": {
            "client_id": "superman",
            "client_secret": "iadJ87dba8b32TfnymdBpVxpLcYsheWL",
            "server_metadata_url": "http://keycloak.local:8180/realms/master/.well-known/openid-configuration",
            "client_kwargs": {"scope": "openid profile email"},
        },
    }
]

LOG_LEVEL = "DEBUG"
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("flask_oauthlib").setLevel(logging.DEBUG)
logging.getLogger("authlib").setLevel(logging.DEBUG)
logging.getLogger("superset.security").setLevel(logging.DEBUG)
logging.getLogger("flask_appbuilder.security").setLevel(logging.DEBUG)

log = logging.getLogger(__name__)

class KeycloakSecurity(SupersetSecurityManager):
    """
    Custom SecurityManager để lấy user info từ Keycloak
    """

    def oauth_user_info(self, provider, resp=None):
        if provider == "tung":
            log.debug("Keycloak response received: %s", resp)
            # Gọi trực tiếp endpoint userinfo
            me = self.appbuilder.sm.oauth_remotes[provider].get(
                "http://keycloak.local:8180/realms/master/protocol/openid-connect/userinfo"
            )
            me.raise_for_status()
            data = me.json()
            log.debug("User info from Keycloak: %s", data)

            return {
                "username": data.get("preferred_username"),
                "first_name": data.get("given_name", ""),
                "last_name": data.get("family_name", ""),
                "email": data.get("email", ""),
                "name": data.get("name", ""),
                "role_keys": data.get("roles", []),  # hoặc groups nếu bạn map theo Keycloak
            }

CUSTOM_SECURITY_MANAGER = KeycloakSecurity

GUEST_ROLE_NAME = 'Gamma'
FEATURE_FLAGS = {
    "EMBEDDED_SUPERSET": True,
}
TALISMAN_CONFIG = {
    "content_security_policy": {
        "base-uri": ["'self'"],
        "default-src": ["'self'"],
        "img-src": [
            "'self'",
            "blob:",
            "data:",
            "https://apachesuperset.gateway.scarf.sh",
            "https://static.scarf.sh/",
        ],
        "worker-src": ["'self'", "blob:"],
        "connect-src": [
            "'self'",
            "https://api.mapbox.com",
            "https://events.mapbox.com",
        ],
        "object-src": "'none'",
        "style-src": [
            "'self'",
            "'unsafe-inline'",
        ],
        "script-src": ["'self'", "'strict-dynamic'"],
        "frame-ancestors": ["http://localhost:8080"]
    },
    "content_security_policy_nonce_in": ["script-src"],
    "force_https": False,
    "session_cookie_secure": False,
}

# # ---- 8. Custom Security Manager ----
# class KeycloakSecurityManager(SupersetSecurityManager):
#     def oauth_user_info(self, provider, response=None):
#         userinfo = self.appbuilder.sm.oauth_remotes[provider].get('userinfo').json()

#         access_token = response.get("access_token")
#         decoded_token = jwt.decode(access_token, options={"verify_signature": False})

#         roles = []

#         # 1. Realm roles
#         if "realm_access" in decoded_token:
#             roles.extend(decoded_token["realm_access"].get("roles", []))

#         # 2. Client roles (resource_access)
#         if "resource_access" in decoded_token:
#             client_roles = decoded_token["resource_access"].get("jmix-app", {}).get("roles", [])
#             roles.extend(client_roles)

#         # 3. Custom claim "roles" (mapper)
#         if "roles" in decoded_token:
#             claim_roles = decoded_token["roles"]
#             if isinstance(claim_roles, list):
#                 roles.extend(claim_roles)
#             elif isinstance(claim_roles, str):
#                 roles.append(claim_roles)

#         return {
#             "username": userinfo.get("preferred_username"),
#             "first_name": userinfo.get("given_name", ""),
#             "last_name": userinfo.get("family_name", ""),
#             "email": userinfo.get("email", ""),
#             "role_keys": roles
#         }



# CUSTOM_SECURITY_MANAGER = KeycloakSecurityManager
