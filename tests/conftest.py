"""Shared pytest fixtures."""

import pytest


@pytest.fixture
def sample_messages():
    return [
        "Hi",
        "Attack at dawn",
        "A",
        "Fire at 0600!!!",
        "Bonjour le monde",
    ]


@pytest.fixture
def default_k():
    return 4


@pytest.fixture
def default_n():
    return 7


@pytest.fixture
def default_prime():
    return (2 ** 127) - 1
