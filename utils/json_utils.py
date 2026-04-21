import datetime
from bson import ObjectId

def mongo_to_json(data):
    """
    Recursively converts MongoDB/BSON types (ObjectId, datetime) 
    into JSON-serializable formats (strings).
    """
    if isinstance(data, dict):
        return {k: mongo_to_json(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [mongo_to_json(v) for v in data]
    elif isinstance(data, ObjectId):
        return str(data)
    elif isinstance(data, datetime.datetime):
        return data.isoformat()
    # Handle potentially other non-serializable types if needed
    return data
