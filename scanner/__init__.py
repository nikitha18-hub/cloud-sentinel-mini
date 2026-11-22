from scanner.security_rules import SECURITY_CHECKS


REQUIRED_CONFIG_KEYS = {
    "public_storage_access",
    "encryption_enabled",
    "logging_enabled",
    "unrestricted_ssh",
    "excessive_iam_admin",
}


def validate_config(config):
    """Check that the configuration has exactly the required boolean settings."""
    if not isinstance(config, dict):
        raise ValueError("Configuration must be a JSON object.")

    missing_keys = REQUIRED_CONFIG_KEYS - config.keys()
    extra_keys = config.keys() - REQUIRED_CONFIG_KEYS
    if missing_keys:
        raise ValueError(f"Missing configuration keys: {', '.join(sorted(missing_keys))}.")
    if extra_keys:
        raise ValueError(f"Unexpected configuration keys: {', '.join(sorted(extra_keys))}.")

    invalid_keys = [key for key in REQUIRED_CONFIG_KEYS if type(config[key]) is not bool]
    if invalid_keys:
        raise ValueError(f"Configuration values must be booleans: {', '.join(sorted(invalid_keys))}.")


def run_scan(config):
    """Evaluate the five simulated infrastructure security settings."""
    validate_config(config)
    results = []

    for check in SECURITY_CHECKS:
        is_risky = config[check["config_key"]] is check["risky_value"]
        results.append(
            {
                "check_name": check["check_name"],
                "status": "RISK DETECTED" if is_risky else "SECURE",
                "risk_level": check["risk_level"],
                "recommendation": check["recommendation"],
            }
        )

    return results


def calculate_score(results):
    """Start at 100 and subtract 20 for high risks and 10 for medium risks."""
    if not isinstance(results, list):
        raise ValueError("Results must be a list.")

    deductions = {"HIGH": 20, "MEDIUM": 10}
    score = 100
    for result in results:
        if not isinstance(result, dict) or result.get("status") not in {
            "SECURE",
            "RISK DETECTED",
            "NOT CHECKED",
        }:
            raise ValueError("Each result must have a valid status.")
        if result["status"] == "RISK DETECTED":
            risk_level = result.get("risk_level")
            if risk_level not in deductions:
                raise ValueError("Risk results must have a valid risk level.")
            score -= deductions[risk_level]

    return max(0, min(100, score))