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