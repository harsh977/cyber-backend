from fastapi import APIRouter, HTTPException
from datetime import datetime, timedelta
from typing import List
from connection.connection import get_uploaded_files_collection
import numpy as np
from typing import Literal
from connection.connection import get_uploaded_files_collection
router = APIRouter()

# Common aggregation stages for latest records
latest_vuln_stages = [
    {
        "$sort": {
            "Plugin Modification Date": -1,
            "IP Address": 1,
            "Plugin Name": 1,
            "Port": 1
        }
    },
    {
        "$group": {
            "_id": {
                "ip": "$IP Address",
                "plugin": "$Plugin Name",
                "port": "$Port"
            },
            "doc": {"$first": "$$ROOT"}
        }
    },
    {"$replaceRoot": {"newRoot": "$doc"}}
]

# 1. Vulnerabilities by Port
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

# 2. Exploit Availability
@router.get("/exploit-availability")
async def get_exploit_availability():
    try:
        collection = await get_uploaded_files_collection()
        pipeline = latest_vuln_stages + [
            {"$group": {
                "_id": "$Exploit?",
                "count": {"$sum": 1}
            }},
            {"$project": {
                "status": {
                    "$cond": [
                        {"$eq": ["$_id", "Yes"]},
                        "Exploit Available",
                        "No Known Exploit"
                    ]
                },
                "count": 1,
                "_id": 0
            }}
        ]
        cursor = collection.aggregate(pipeline)
        results = await cursor.to_list(length=None)
        return results
    except Exception as e:
        raise HTTPException(500, f"Error: {str(e)}")

# 3. Top Vulnerabilities by Plugin
@router.get("/top-vulnerabilities")
async def get_top_vulnerabilities(limit: int = 10):
    try:
        collection = await get_uploaded_files_collection()
        pipeline = latest_vuln_stages + [
            {"$group": {"_id": "$Plugin Name", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": limit},
            {"$project": {"plugin": "$_id", "count": 1, "_id": 0}}
        ]
        cursor = collection.aggregate(pipeline)
        return await cursor.to_list(length=None)
    except Exception as e:
        raise HTTPException(500, f"Error: {str(e)}")

# 4. Vulnerability Trend Over Time
@router.get("/vulnerability-trend")
async def get_vulnerability_trend(granularity: Literal["monthly", "yearly"] = "monthly"):
    try:
        collection = await get_uploaded_files_collection()
        date_format = "%Y-%m" if granularity == "monthly" else "%Y"
        
        pipeline = latest_vuln_stages + [
            # Parse the date field
            {
                "$addFields": {
                    "pub_date": {
                        "$dateFromString": {
                            "dateString": "$Vuln Publication Date",
                            "format": "%b %d, %Y %H:%M",  # Updated format to match the actual date string
                            "onError": None,  # Returns null for invalid dates
                            "timezone": "Asia/Kolkata"
                        }
                    }
                }
            },
            # Filter out documents where pub_date is null
            {
                "$match": {
                    "pub_date": {"$ne": None}
                }
            },
            # Group by the specified granularity
            {
                "$group": {
                    "_id": {
                        "$dateToString": {
                            "format": date_format,
                            "date": "$pub_date"
                        }
                    },
                    "count": {"$sum": 1}
                }
            },
            # Sort by date
            {
                "$sort": {"_id": 1}
            },
            # Project the final output
            {
                "$project": {
                    "date": "$_id",
                    "count": 1,
                    "_id": 0
                }
            }
        ]
        
        cursor = collection.aggregate(pipeline)
        result = await cursor.to_list(length=None)
        
        if not result:
            return []  # Return empty list if no valid data found
        
        return result
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

# 5. Vulnerabilities by Risk Factor
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

# 6. Most Affected Protocols
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
