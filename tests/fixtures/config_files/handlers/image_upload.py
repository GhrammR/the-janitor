"""Image upload handler - Referenced in serverless.yml."""


def upload_image(event, context):
    """Lambda handler for image uploads.

    This function is referenced in serverless.yml as:
    handler: handlers.image_upload.upload_image

    Should be PROTECTED by config parser.
    """
    return {
        'statusCode': 200,
        'body': 'Image uploaded successfully'
    }


def helper_function():
    """Helper function - NOT referenced in config, should be dead."""
    return "This is unused"
