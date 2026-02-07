"""Image processor handler - Referenced in serverless.yml."""


def process_image(event, context):
    """Lambda handler for image processing.

    Referenced in serverless.yml as:
    handler: handlers.image_processor.process_image

    Should be PROTECTED by config parser.
    """
    return {'statusCode': 200, 'body': 'Image processed'}


def internal_resize():
    """Internal function - NOT in config, should be dead."""
    pass
