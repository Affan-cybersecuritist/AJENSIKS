import pytest
from generated_app import init_database, search_records

@pytest.fixture
def db():
    return init_database()

def test_search_existing_record(db):
    results = search_records(db, "admin_note")
    assert len(results) == 1
    assert results[0][1] == "admin_note"

def test_search_nonexistent_record(db):
    results = search_records(db, "unknown")
    assert len(results) == 0
