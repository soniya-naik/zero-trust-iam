def check_access(role, risk_score):
    """
    Zero Trust Policy Engine

    role:
        User's role such as admin or user.

    risk_score:
        Security risk score of the target.
        0 = safest
        100 = highest risk
    """

    # High-risk targets should not be accessed
    if risk_score >= 70:
        return {
            "decision": "DENY",
            "reason": "Target security risk is too high"
        }

    # Admin users can access low-risk targets
    if role == "admin" and risk_score < 70:
        return {
            "decision": "ALLOW",
            "reason": "Admin user verified and target risk is acceptable"
        }

    # Normal users can access only low-risk targets
    if role == "user" and risk_score < 40:
        return {
            "decision": "ALLOW",
            "reason": "User verified and target risk is low"
        }

    # Medium-risk access requires additional verification
    return {
        "decision": "STEP_UP",
        "reason": "Additional authentication is required"
    }