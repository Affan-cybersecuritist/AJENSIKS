import pytest
from app import init_db, authenticate_user

@pytest.fixture
def db_conn():
    return init_db()

def test_successful_login(db_conn):
    assert authenticate_user(db_conn, "admin", "secret123") is True

def test_failed_login_wrong_password(db_conn):
    assert authenticate_user(db_conn, "admin", "wrongpass") is False

def test_failed_login_nonexistent_user(db_conn):
    assert authenticate_user(db_conn, "ghost", "secret123") is False
