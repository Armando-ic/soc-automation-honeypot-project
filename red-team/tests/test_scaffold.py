def test_package_imports():
    import red_team
    import red_team.harness
    assert red_team is not None


def test_public_entry_points_import():
    # Load-bearing: a broken submodule (bad import, renamed symbol) fails HERE
    # instead of silently passing a tautological `is not None` check. These are
    # the public entry points the harness is built around.
    from red_team.scorer import score_trial
    from red_team.cases import load_cases
    from red_team.stats import clopper_pearson

    assert callable(score_trial)
    assert callable(load_cases)
    assert callable(clopper_pearson)
