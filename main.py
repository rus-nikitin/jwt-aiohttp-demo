import base64
from cryptography import fernet
from aiohttp import web
from aiohttp_session import setup as setup_session
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from aiohttp_security import setup as setup_security

from authz import DictionaryAuthorizationPolicy, ImplJWTIdentityPolicy
from handlers import configure_handlers
from users import user_map

from types import MappingProxyType
from typing import Mapping
from aiohttp import PAYLOAD_REGISTRY, JsonPayload

PAYLOAD_REGISTRY.register(JsonPayload, (Mapping, MappingProxyType))


def make_app():
    app = web.Application()
    app.user_map = user_map
    configure_handlers(app)

    # secret_key must be 32 url-safe base64-encoded bytes
    fernet_key = fernet.Fernet.generate_key()
    secret_key = base64.urlsafe_b64decode(fernet_key)

    storage = EncryptedCookieStorage(secret_key, cookie_name='API_SESSION')
    setup_session(app, storage)

    policy = ImplJWTIdentityPolicy(secret_key)
    setup_security(app, policy, DictionaryAuthorizationPolicy(user_map))

    return app


if __name__ == '__main__':
    web.run_app(make_app(), port=9000)
