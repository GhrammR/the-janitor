"""Cleanup jobs - Referenced in serverless.yml."""

def cleanup_old_images(event, context):
    """Referenced: jobs.cleanup.cleanup_old_images - Should be PROTECTED."""
    return {'statusCode': 200}
