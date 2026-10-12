import pandas as pd
import re
import joblib

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report


# Step 1: Load the dataset
data = pd.read_csv(
    "SMSSpamCollection",
    sep="\t",
    header=None,
    names=["label", "message"],
    encoding="utf-8"
)

# Step 2: Clean the messages
def clean_text(text):
    text = str(text).lower()
    text = re.sub(r"http\S+|www\.\S+", " URL ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


data["message"] = data["message"].apply(clean_text)

# Step 3: Prepare the input and output
X = data["message"]
y = data["label"]

# Step 4: Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# Step 5: Build the AI model
model = Pipeline([
    ("tfidf", TfidfVectorizer()),
    ("classifier", LogisticRegression(max_iter=1000))
])

# Step 6: Train the model
model.fit(X_train, y_train)

# Step 7: Test the model
predictions = model.predict(X_test)

print("\nMODEL PERFORMANCE")
print(classification_report(y_test, predictions))

# Step 8: Save the trained model
joblib.dump(model, "scam_model.pkl")

print("AI model trained and saved successfully!")