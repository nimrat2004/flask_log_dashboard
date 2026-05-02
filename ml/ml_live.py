import joblib

def load_models():
    iso_model = joblib.load("iso_model.pkl")
    kmeans = joblib.load("kmeans.pkl")
    scaler = joblib.load("scaler.pkl")

    return iso_model, kmeans, scaler