class URLhausError(Exception):
    pass

class URLhausAuthError(URLhausError):
    pass

class URLhausRateLimitError(URLhausError):
    pass

class URLhausValidationError(URLhausError):
    pass

class URLhausUnsafeInputError(URLhausValidationError):
    pass

class URLhausProviderError(URLhausError):
    pass

class URLhausSubmissionDisabledError(URLhausError):
    pass

class URLhausMalwareDownloadDisabledError(URLhausError):
    pass
