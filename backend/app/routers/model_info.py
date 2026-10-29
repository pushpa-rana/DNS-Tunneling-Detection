from fastapi import APIRouter, HTTPException
from app.ml.model import model_manager

router = APIRouter(prefix="/model", tags=["Model Insights"])

@router.get("/info")
def get_model_information():
    if not model_manager.is_loaded():
        model_manager.load_or_train()

    if not model_manager.metrics:
        raise HTTPException(status_code=500, detail="Model metrics are not available.")

    return model_manager.metrics

@router.post("/retrain")
def retrain_model():
    try:
        new_metrics = model_manager.train_and_save(num_samples=4000)
        return {
            "status": "SUCCESS",
            "message": "Model retrained and evaluated successfully with updated dataset.",
            "metrics": new_metrics
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Model retraining failed: {str(e)}")
