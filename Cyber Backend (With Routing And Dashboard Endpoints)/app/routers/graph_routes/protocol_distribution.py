from fastapi import APIRouter, HTTPException
from connection.connection import get_uploaded_files_collection
from utils.aggregations import latest_vuln_stages

router = APIRouter()

@router.get("/protocol-distribution")
async def get_protocol_distribution():
    try:
        collection = await get_uploaded_files_collection()
        pipeline = latest_vuln_stages + [
            {"$group": {"_id": "$Protocol", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$project": {"protocol": "$_id", "count": 1, "_id": 0}}
        ]
        cursor = collection.aggregate(pipeline)
        return await cursor.to_list(length=None)
    except Exception as e:
        raise HTTPException(500, f"Error: {str(e)}")