from aiohttp import web
from aiohttp_security import (
    remember, forget,
    check_permission,
)

from authz import check_credentials


async def login(request):
    data = await request.json()
    username = data.get('username')
    password = data.get('password')

    verified = await check_credentials(request.app.user_map, username, password)
    if verified:
        response = web.Response()
        await remember(request, response, username)
        return response

    body = {"msg": "Invalid username / password combination"}
    return web.HTTPUnauthorized(body=body)


async def refresh(request):  # TODO need api extension and refactoring
    response = web.Response()
    await forget(request, response)

    return response


async def internal_page(request):
    await check_permission(request, 'public')

    body = {"msg": "This page is visible for all registered users"}
    return web.Response(body=body)


async def protected_page(request):
    await check_permission(request, 'protected')

    body = {"msg": "You are on protected page"}
    return web.Response(body=body)


def configure_handlers(app):
    router = app.router
    router.add_post('/login', login, name='login')
    router.add_get('/refresh', refresh, name='refresh')
    router.add_get('/public', internal_page, name='public')
    router.add_get('/protected', protected_page, name='protected')
