import jwt
from datetime import datetime, timedelta
from aiohttp_security.abc import AbstractAuthorizationPolicy
from aiohttp_security import JWTIdentityPolicy


AUTH_HEADER_NAME = 'Authorization'
REFRESH_HEADER_NAME = 'Refresh'
AUTH_SCHEME = 'Bearer '


async def extract_token(request, response, header_name):
    header_identity = request.headers.get(header_name)
    if header_identity is None:
        response.set_status(400)
        response.body = {"msg": f"Invalid header scheme. Should be '{header_name}'"}
        return None

    if not header_identity.startswith(AUTH_SCHEME):
        response.set_status(400)
        response.body = {"msg": f"Invalid token scheme. Should be '{AUTH_SCHEME} <token>'"}
        return None

    return header_identity.split(' ')[2].strip()


class ImplJWTIdentityPolicy(JWTIdentityPolicy):
    def __init__(self, secret, algorithm='HS256'):
        JWTIdentityPolicy.__init__(self, secret, algorithm=algorithm)
        self.tokens = {}

    async def identify(self, request):
        header_identity = request.headers.get(AUTH_HEADER_NAME)

        if header_identity is None:
            return

        if not header_identity.startswith(AUTH_SCHEME):
            raise ValueError('Invalid authorization scheme. ' +
                             'Should be `Bearer <token>`')

        token = header_identity.split(' ')[2].strip()

        try:
            identity = jwt.decode(token, self.secret, algorithms=[self.algorithm])
        except jwt.ExpiredSignatureError:
            return

        return identity['user']

    async def remember(self, *args, **kwargs):
        user = args[2]
        # timedelta 1-2 minutes for test only
        dt = datetime.now() + timedelta(minutes=1)
        access_token = await self.get_token(user=user, dt=dt)
        dt = datetime.now() + timedelta(minutes=2)
        refresh_token = await self.get_token(user=user, dt=dt)
        args[1].headers.add(AUTH_HEADER_NAME, f"{AUTH_SCHEME} {access_token}")
        args[1].headers.add(REFRESH_HEADER_NAME, f"{AUTH_SCHEME} {refresh_token}")
        self.tokens[user] = (access_token, refresh_token)

    async def forget(self, request, response):
        access_token = await extract_token(request, response, AUTH_HEADER_NAME)
        refresh_token = await extract_token(request, response, REFRESH_HEADER_NAME)
        if access_token is None or refresh_token is None:
            return
        try:
            identity = jwt.decode(refresh_token, self.secret, algorithms=[self.algorithm])
        except jwt.ExpiredSignatureError:
            response.set_status(403)
            response.body = {"msg": "Signature has expired"}
            return

        user = identity['user']
        if self.tokens[user] == (access_token, refresh_token):
            await self.remember(None, response, user)
        else:
            response.set_status(401)

    async def get_token(self, user, dt):
        token = jwt.encode({
            'user': user,
            'exp': int(dt.strftime('%s'))
        }, self.secret, self.algorithm)
        return token


class DictionaryAuthorizationPolicy(AbstractAuthorizationPolicy):
    def __init__(self, user_map):
        super().__init__()
        self.user_map = user_map

    async def authorized_userid(self, identity):
        """Retrieve authorized user id.
        Return the user_id of the user identified by the identity
        or 'None' if no user exists related to the identity.
        """
        if identity in self.user_map:
            return identity

    async def permits(self, identity, permission, context=None):
        """Check user permissions.
        Return True if the identity is allowed the permission in the
        current context, else return False.
        """
        # pylint: disable=unused-argument
        user = self.user_map.get(identity)
        if not user:
            return False
        return permission in user.permissions


async def check_credentials(user_map, username, password):
    user = user_map.get(username)
    if not user:
        return False

    return user.password == password
