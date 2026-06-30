class AbuseIPDBError(Exception):
    pass

class AbuseIPDBAuthError(AbuseIPDBError):
    pass

class AbuseIPDBRateLimitError(AbuseIPDBError):
    pass

class AbuseIPDBValidationError(AbuseIPDBError):
    pass

class AbuseIPDBPlanLimitError(AbuseIPDBError):
    pass

class AbuseIPDBProviderError(AbuseIPDBError):
    pass
