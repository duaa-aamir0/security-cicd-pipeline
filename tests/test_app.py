# basic tests for flask app

import pytest
from app.app import app

# ceate a test client
@pytest.fixture
def client():       
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

# Test home page returns 200
def test_home(client):
    response = client.get('/')
    assert response.status_code == 200
    assert b'Welcome' in response.data

# test health endpoint
def test_health(client):
    response = client.get('/health')
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'healthy'

# test echo endpoint
def test_echo(client):
    response = client.post('/api/echo', json={'message': 'test'})
    assert response.status_code == 200
    data = response.get_json()
    assert 'echo' in data