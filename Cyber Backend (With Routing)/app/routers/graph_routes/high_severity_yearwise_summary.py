from fastapi import APIRouter, HTTPException
import pandas as pd
import numpy as np
from connection.connection import get_uploaded_files_collection

router = APIRouter()

@router.get("/high-severity-yearwise-summary")
async def get_high_severity_yearwise_summary():
    try:
        collection = await get_uploaded_files_collection()
        records = await collection.find({}).to_list(length=None)

        if not records:
            return {"message": "No records found"}

        df = pd.DataFrame(records)

        # Convert relevant date columns
        df["Vuln Publication Date"] = pd.to_datetime(df.get("Vuln Publication Date"), errors="coerce")
        df["Patch Publication Date"] = pd.to_datetime(df.get("Patch Publication Date"), errors="coerce")

        # Filter high severity only
        df_high = df[df["Severity"].str.strip().str.lower() == "high"].copy()

        # Drop rows with no vuln date
        df_high = df_high[df_high["Vuln Publication Date"].notnull()]

        # Create incident key
        df_high["Incident Key"] = (
            df_high["IP Address"].astype(str) + "-" +
            df_high["Plugin Name"].astype(str) + "-" +
            df_high["Port"].astype(str)
        )

        result = {}

        for year in sorted(df_high["Vuln Publication Date"].dt.year.unique()):
            year_df = df_high[df_high["Vuln Publication Date"].dt.year == year]
            total_incidents = year_df["Incident Key"].nunique()

            resolved = year_df[
                (year_df["Patch Publication Date"].notnull()) &
                (year_df["Patch Publication Date"].dt.year <= year)
            ]["Incident Key"].nunique()

            result[int(year)] = {
                "total_high_incidents": total_incidents,
                "resolved_by_year_end": resolved
            }

        return result

    except Exception as e:
        raise HTTPException(500, f"Error generating summary: {str(e)}")