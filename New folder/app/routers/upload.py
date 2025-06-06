from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
import pandas as pd
from io import StringIO
from datetime import datetime
import numpy as np

from connection.connection import get_uploaded_files_collection

router = APIRouter()

@router.post("/upload")
async def upload_csv(file: UploadFile = File(...)):
    if not file.filename.endswith(".csv"):
        raise HTTPException(400, "Only CSV files supported")

    try:
        contents = await file.read()
        df = pd.read_csv(StringIO(contents.decode("utf-8")))
        records = df.replace({np.nan: None}).to_dict("records")
        
        collection = await get_uploaded_files_collection()
        
        if records:
            # Delete all existing records
            await collection.delete_many({})
            # Insert new records
            result = await collection.insert_many(records)
            
        return {"message": f"Replaced existing data with {len(records)} new records"}

    except Exception as e:
        raise HTTPException(500, f"Processing failed: {str(e)}")

@router.get("/severity-counts")
async def get_severity_counts():
    try:
        collection = await get_uploaded_files_collection()
        
        # Get all records
        cursor = collection.find({})
        records = await cursor.to_list(length=None)
        
        if not records:
            return {"message": "No records found"}
            
        # Convert to DataFrame for easier processing
        df = pd.DataFrame(records)
        
        # Convert date columns to datetime
        date_columns = ['Vuln Publication Date', 'Patch Publication Date', 'Plugin Publication Date']
        for col in date_columns:
            if col in df.columns:
                df[col] = pd.to_datetime(df[col], errors='coerce')
        
        # Use Plugin Publication Date as the main date
        if 'Plugin Publication Date' in df.columns:
            df['Date'] = df['Plugin Publication Date']
        else:
            raise ValueError("Plugin Publication Date column is missing")
            
        # Sort by date and get latest record for each IP+Plugin+Port combination
        df = df.sort_values('Date')
        latest_records = df.groupby(['IP Address', 'Plugin Name', 'Port']).last().reset_index()
        
        # Count severities
        severity_counts = {
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }
        
        # Count each severity level
        for severity in latest_records['Severity']:
            if pd.isna(severity):
                severity_counts['Info'] += 1
            else:
                severity = str(severity).strip()
                if severity in severity_counts:
                    severity_counts[severity] += 1
                else:
                    severity_counts['Info'] += 1
        
        return {
            "severity_counts": severity_counts,
            "total_records": len(latest_records)
        }
        
    except Exception as e:
        raise HTTPException(500, f"Failed to calculate severity counts: {str(e)}")
    
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
    

@router.get("/patch-availability")
async def get_patch_availability():
    try:
        collection = await get_uploaded_files_collection()
        records = await collection.find({}).to_list(length=None)
        
        if not records:
            return {"patched": 0, "unpatched": 0}
            
        df = pd.DataFrame(records)
        
        # Convert date columns to datetime
        date_columns = ['Plugin Modification Date', 'Plugin Publication Date', 'Patch Publication Date']
        for col in date_columns:
            if col in df.columns:
                df[col] = pd.to_datetime(df[col], errors='coerce')
        
        # Prioritize Plugin Modification Date over Publication Date for sorting
        if 'Plugin Modification Date' in df.columns:
            df['SortDate'] = df['Plugin Modification Date']
        elif 'Plugin Publication Date' in df.columns:
            df['SortDate'] = df['Plugin Publication Date']
        else:
            raise ValueError("Neither Plugin Modification Date nor Publication Date columns found")
        
        # Sort by date and get the latest record for each unique vulnerability
        # This ensures we use the most up-to-date detection for each vulnerability
        df = df.sort_values('SortDate', ascending=True)  # Ascending so the last record is the latest
        latest_records = df.groupby(['IP Address', 'Plugin Name', 'Port']).last().reset_index()
        
        # Count patched vs. unpatched vulnerabilities
        patched = latest_records[latest_records['Patch Publication Date'].notna()].shape[0]
        unpatched = latest_records[latest_records['Patch Publication Date'].isna()].shape[0]
        
        return {
            "patched": patched,
            "unpatched": unpatched,
            "total": patched + unpatched
        }
        
    except Exception as e:
        raise HTTPException(500, f"Failed to calculate patch availability: {str(e)}")

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
