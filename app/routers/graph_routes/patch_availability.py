from fastapi import APIRouter, HTTPException
import pandas as pd
from connection.connection import get_uploaded_files_collection

router = APIRouter()

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