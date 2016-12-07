import logging
import os

from pytest import fixture, yield_fixture

from mockssh import Server, User


__all__ = [
    "server",
]


SAMPLE_USER_KEY = os.path.join(os.path.dirname(__file__), "sample-user-key")


@fixture
def user_key_path():
    return SAMPLE_USER_KEY

@yield_fixture(scope="function")
def server():
    users = [
                User(uid="sample-user", private_key_path=SAMPLE_USER_KEY),
                User(uid="password-user", password='12345'),
            ]
    with Server(users) as s:
        yield s


logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s %(threadName)s %(name)s %(message)s")
