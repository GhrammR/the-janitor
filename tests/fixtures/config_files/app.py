"""SAM app handlers - Referenced in template.yaml."""

def lambda_handler(event, context):
    """Referenced: app.lambda_handler - Should be PROTECTED."""
    return {'statusCode': 200}

def unused_app_function():
    """Not referenced - should be dead."""
    pass
