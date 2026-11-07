
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List

from app.engines.anomaly import detect_anomaly

router = APIRouter(
    prefix="/anomaly",
    tags=["Statistical Anomaly Detection"]
)


class AnomalyRequest(BaseModel):
    traffic_data: List[float] = Field(
        ..., min_length=2,
        description="Baseline network traffic measurements"
    )
    current_value: float = Field(
        ..., description="Current network traffic measurement"
    )
    threshold: float = Field(
        default=3, gt=0,
        description="Z-score threshold for anomaly detection"
    )


@router.post("/analyze")
def analyze_traffic(request: AnomalyRequest):
    try:
        result = detect_anomaly(
            request.traffic_data,
            request.current_value,
            request.threshold
        )
        return result
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
