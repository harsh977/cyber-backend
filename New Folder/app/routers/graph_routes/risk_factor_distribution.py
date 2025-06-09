from fastapi import APIRouter, HTTPException
from connection.connection import get_uploaded_files_collection
from utils.aggregations import latest_vuln_stages

router = APIRouter()

@router.get("/risk-factor-distribution")
async def get_risk_factor_distribution():
    try:
        collection = await get_uploaded_files_collection()
        pipeline = latest_vuln_stages + [
            {"$group": {
                "_id": {
                    "ip": "$IP Address",
                    "risk": "$Risk Factor"
                },
                "count": {"$sum": 1}
            }},
            {"$group": {
                "_id": "$_id.ip",
                "risks": {
                    "$push": {
                        "risk": "$_id.risk",
                        "count": "$count"
                    }
                }
            }},
            {"$project": {
                "ip": "$_id",
                "risks": 1,
                "_id": 0
            }}
        ]
        cursor = collection.aggregate(pipeline)
        return await cursor.to_list(length=None)
    except Exception as e:
        raise HTTPException(500, f"Error: {str(e)}")