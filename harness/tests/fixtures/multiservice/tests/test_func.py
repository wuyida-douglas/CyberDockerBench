import json
import time
import urllib.request


def application_state():
    for _ in range(60):
        try:
            with urllib.request.urlopen('http://127.0.0.1:8080/state', timeout=2) as response:
                return json.load(response)
        except Exception:
            time.sleep(1)
    raise AssertionError('application did not become ready')


def test_real_service_and_persisted_data():
    state = application_state()
    assert state['counter'] == '42'
    assert state['bind'] == 'bind-asset-preserved'
    assert state['anonymous'] == 'anonymous-volume-preserved'


def test_patchable_setting_is_readable():
    assert application_state()['setting'] in ('vulnerable', 'fixed')
