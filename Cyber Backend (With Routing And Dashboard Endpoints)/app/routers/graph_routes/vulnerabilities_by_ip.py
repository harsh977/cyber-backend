from fastapi import APIRouter, HTTPException
from connection.connection import get_uploaded_files_collection

router = APIRouter()

@router.get("/vulnerabilities-by-ip")
async def get_vulnerabilities_by_ip():
    try:
        collection = await get_uploaded_files_collection()
        
        pipeline = [
            {
                "$group": {
                    "_id": "$IP Address",
                    "vulnerability_count": {"$sum": 1},
                    "unique_plugins": {"$addToSet": "$Plugin Name"}
                }
            },
            {
                "$project": {
                    "_id": 0,
                    "ip": "$_id",
                    "total_vulnerabilities": "$vulnerability_count",
                    "unique_plugins_count": {"$size": "$unique_plugins"}
                }
            },
            {
                "$sort": {"total_vulnerabilities": -1}
            }
        ]

        cursor = collection.aggregate(pipeline)
        results = await cursor.to_list(length=None)
        
        return {"vulnerabilities_by_ip": results}

    except Exception as e:
        raise HTTPException(500, f"Failed to calculate IP vulnerabilities: {str(e)}")