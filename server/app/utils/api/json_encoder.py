from datetime import datetime
import json
from uuid import UUID


class CustomJSONEncoder(json.JSONEncoder):
    """
    Custom JSON encoder to handle UUID and datetime serialization
    """

    def default(self, obj):
        if isinstance(obj, UUID):

            return str(obj)
        if isinstance(obj, datetime):

            return obj.isoformat()

        return super().default(obj)
