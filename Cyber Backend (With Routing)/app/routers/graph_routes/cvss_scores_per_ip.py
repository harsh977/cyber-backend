from fastapi import APIRouter, HTTPException
import pandas as pd
from connection.connection import get_uploaded_files_collection

router = APIRouter()

@router.get("/cvss-scores-per-ip")
async def get_cvss_scores_per_ip():
    try:
        collection = await get_uploaded_files_collection()
        records = await collection.find({}).to_list(length=None)

        if not records:
            return {"message": "No records found"}

        df = pd.DataFrame(records)

        # Check and convert score columns to numeric
        if 'CVSS V2 Base Score' in df.columns:
            df['CVSS V2 Base Score'] = pd.to_numeric(df['CVSS V2 Base Score'], errors='coerce')
        else:
            df['CVSS V2 Base Score'] = None

        if 'CVSS V3 Base Score' in df.columns:
            df['CVSS V3 Base Score'] = pd.to_numeric(df['CVSS V3 Base Score'], errors='coerce')
        else:
            df['CVSS V3 Base Score'] = None

        # Group by IP and compute average scores
        result = {}
        grouped = df.groupby("IP Address")

        for ip, group in grouped:
            v2_scores = group["CVSS V2 Base Score"].dropna().tolist()
            v3_scores = group["CVSS V3 Base Score"].dropna().tolist()

            avg_v2 = round(sum(v2_scores) / len(v2_scores), 2) if v2_scores else None
            avg_v3 = round(sum(v3_scores) / len(v3_scores), 2) if v3_scores else None

            result[ip] = {
                "average_cvss_v2": avg_v2,
                "average_cvss_v3": avg_v3
            }

        return result

    except Exception as e:
        raise HTTPException(500, f"Failed to retrieve CVSS scores per IP: {str(e)}")