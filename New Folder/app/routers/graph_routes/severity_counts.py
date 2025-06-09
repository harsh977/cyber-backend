from fastapi import APIRouter, HTTPException
import pandas as pd
from connection.connection import get_uploaded_files_collection

router = APIRouter()

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