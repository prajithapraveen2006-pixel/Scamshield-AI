import joblib

# Load the trained AI model
model = joblib.load("scam_model.pkl")

print("\n==============================")
print("       SCAMSHIELD AI")
print("  SMS Spam Detection System")
print("==============================")

while True:
    message = input("\nEnter a message (or type exit): ")

    if message.lower() == "exit":
        print("Thank you for using ScamShield AI!")
        break

    prediction = model.predict([message])[0]

    if prediction == "spam":
        print("\nWARNING: This message may be SPAM!")
    else:
        print("\nThis message appears to be LEGITIMATE.")

    print("Note: AI predictions may not always be correct.")