"""Analytics worker - Referenced in serverless.yml."""

def process_analytics(event, context):
    """Referenced: workers.analytics_worker.process_analytics - Should be PROTECTED."""
    return {'statusCode': 200}

def unused_worker_function():
    """Not referenced - should be dead."""
    pass
