"""Custom authorizer - Referenced in serverless.yml."""

def validate_token(event, context):
    """Referenced: auth.authorizer.validate_token - Should be PROTECTED."""
    return {'statusCode': 200}
