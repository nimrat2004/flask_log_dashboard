import joblib
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans
from app import app, db, PacketLog

def fetch_data():
    with app.app_context():
        logs = PacketLog.query.limit(1000).all()

        data = []

        for log in logs:
            protocol_map = {"TCP": 1, "UDP": 2, "ICMP": 3}

            data.append([
                log.packet_size,
                log.dst_port if log.dst_port else 0,
                protocol_map.get(log.protocol, 0)
            ])

        return pd.DataFrame(data, columns=["packet_size", "dst_port", "protocol"])


def train():
    df = fetch_data()

    # Scale
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(df)

    # Models
    iso_model = IsolationForest(contamination=0.02)
    iso_model.fit(X_scaled)

    kmeans = KMeans(n_clusters=2)
    kmeans.fit(X_scaled)

    # Save models
    joblib.dump(iso_model, "iso_model.pkl")
    joblib.dump(kmeans, "kmeans.pkl")
    joblib.dump(scaler, "scaler.pkl")

    print("Models trained and saved!")


if __name__ == "__main__":
    train()