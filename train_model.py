# train_model.py
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

def generate_demo_dataset(n=600):
    rng = np.random.RandomState(0)
    X = []
    y = []
    for i in range(n):
        # make two classes: benign (0) and phish (1)
        if i < n*0.6:
            length = rng.randint(5, 18)
            special = rng.randint(0,2)
            digits = rng.randint(0,2)
            entropy = rng.uniform(2.5, 4.0)
            age_days = rng.randint(365, 5000)
            has_form = rng.choice([0,1], p=[0.7,0.3])
            js_obf = rng.choice([0,1], p=[0.85,0.15])
            label = 0
        else:
            length = rng.randint(10, 45)
            special = rng.randint(0,6)
            digits = rng.randint(0,6)
            entropy = rng.uniform(1.0, 3.0)
            age_days = rng.randint(0, 365)
            has_form = rng.choice([0,1], p=[0.25,0.75])
            js_obf = rng.choice([0,1], p=[0.4,0.6])
            label = 1
        X.append([length, special, digits, entropy, age_days, has_form, js_obf])
        y.append(label)
    df = pd.DataFrame(X, columns=["length","special_chars","digits","entropy","age_days","has_form","js_obf"])
    df["label"] = y
    return df

def train_and_save(path="lexical_model.pkl"):
    df = generate_demo_dataset(800)
    X = df.drop(columns=["label"])
    y = df["label"]
    X_train,X_test,y_train,y_test = train_test_split(X,y,test_size=0.2, random_state=42)
    clf = RandomForestClassifier(n_estimators=150, random_state=42)
    clf.fit(X_train, y_train)
    print("train score:", clf.score(X_train, y_train))
    print("test score:", clf.score(X_test, y_test))
    joblib.dump(clf, path)
    print("Saved model to", path)

if __name__ == "__main__":
    import imagehash
    print(imagehash.__version__)

