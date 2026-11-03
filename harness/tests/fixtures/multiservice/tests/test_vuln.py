from test_func import application_state


def test_vulnerability_is_fixed():
    assert application_state()['setting'] == 'fixed', 'live setting is still vulnerable'
