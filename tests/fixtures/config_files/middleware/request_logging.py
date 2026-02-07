"""Django middleware - Referenced in settings.py MIDDLEWARE."""

class RequestLoggingMiddleware:
    """Referenced: middleware.request_logging.RequestLoggingMiddleware - Should be PROTECTED."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)


def unused_logging_helper():
    """Not referenced - should be dead."""
    pass
