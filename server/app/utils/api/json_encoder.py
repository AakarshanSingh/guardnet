from datetime import datetime
import json
from uuid import UUID


class CustomJSONEncoder(json.JSONEncoder):
    """
    Custom JSON encoder to handle UUID and datetime serialization
    """

    def default(self, obj):
        if isinstance(obj, UUID):
            # Convert UUID to string
            return str(obj)
        if isinstance(obj, datetime):
            # Convert datetime to ISO format string
            return obj.isoformat()
        # Let the base class handle other types or raise TypeError
        return super().default(obj)
