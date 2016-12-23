import logging
import os

from pytest import fixture, yield_fixture

from mockssh import Server, User


__all__ = [
    "server",
]


SAMPLE_USER_KEY = os.path.join(os.path.dirname(__file__), "sample-user-key")
SAMPLE_USER_PASSWORDED_KEY = os.path.join(os.path.dirname(__file__), "sample-user-passworded-key")


@fixture
def user_key_path():
    return SAMPLE_USER_KEY

@yield_fixture(scope="function")
def server():
    users = [
                User(uid="sample-user", private_key_path=SAMPLE_USER_KEY),
                User(uid="sample-user", private_key_path=SAMPLE_USER_PASSWORDED_KEY, private_key_password='qwerty'),
                User(uid="password-user", password='qwerty'),
            ]
    with Server(users) as s:
        yield s


logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s %(threadName)s %(name)s %(message)s")
