from fastapi import APIRouter, HTTPException
from connection.connection import get_uploaded_files_collection
from utils.aggregations import latest_vuln_stages

router = APIRouter()

@router.get("/vulnerabilities-by-port")
async def get_vulnerabilities_by_port(limit: int = 10):
    try:
        collection = await get_uploaded_files_collection()
        pipeline = latest_vuln_stages + [
            {"$group": {"_id": "$Port", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": limit},
            {"$project": {"port": "$_id", "count": 1, "_id": 0}}
        ]
        cursor = collection.aggregate(pipeline)
        return await cursor.to_list(length=None)
    except Exception as e:
        raise HTTPException(500, f"Error: {str(e)}")