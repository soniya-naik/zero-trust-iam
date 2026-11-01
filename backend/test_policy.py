from policy import check_access


def test_user_low_risk():
    result = check_access("user", 20)
    assert result["decision"] == "ALLOW"


def test_user_medium_risk():
    result = check_access("user", 50)
    assert result["decision"] == "STEP_UP"


def test_user_high_risk():
    result = check_access("user", 85)
    assert result["decision"] == "DENY"


def test_admin_medium_risk():
    result = check_access("admin", 50)
    assert result["decision"] == "ALLOW"


def test_admin_high_risk():
    result = check_access("admin", 85)
    assert result["decision"] == "DENY"

def test_admin_risk_exactly_70():
    result = check_access("admin", 70)
    assert result["decision"] == "DENY"


if __name__ == "__main__":
    tests = [
        test_user_low_risk,
        test_user_medium_risk,
        test_admin_risk_exactly_70,
        test_user_high_risk,
        test_admin_medium_risk,
        test_admin_high_risk,
    ]

    for test in tests:
        test()
        print(f"PASS: {test.__name__}")

    print(f"\nAll {len(tests)} policy tests passed!")