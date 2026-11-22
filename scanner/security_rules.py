SECURITY_CHECKS = (
    {
        "config_key": "public_storage_access",
        "check_name": "Public Storage Access",
        "risky_value": True,
        "risk_level": "HIGH",
        "recommendation": "Block public access and allow only approved identities.",
    },
    {
        "config_key": "encryption_enabled",
        "check_name": "Storage Encryption",
        "risky_value": False,
        "risk_level": "HIGH",
        "recommendation": "Enable encryption for stored data.",
    },
    {
        "config_key": "logging_enabled",
        "check_name": "Audit Logging",
        "risky_value": False,
        "risk_level": "MEDIUM",
        "recommendation": "Enable audit logging and review the logs regularly.",
    },
    {
        "config_key": "unrestricted_ssh",
        "check_name": "Unrestricted SSH Access",
        "risky_value": True,
        "risk_level": "HIGH",
        "recommendation": "Limit SSH access to trusted IP addresses.",
    },
    {
        "config_key": "excessive_iam_admin",
        "check_name": "Excessive IAM Admin Privileges",
        "risky_value": True,
        "risk_level": "HIGH",
        "recommendation": "Grant only the permissions each identity needs.",
    },
)