import tkinter as tk
from tkinter import messagebox
import joblib
import re

from database import (
    create_database,
    save_history,
    get_history,
    get_statistics
)


# ==========================================
# LOAD THE TRAINED AI MODEL
# ==========================================

try:
    model = joblib.load("scam_model.pkl")
except Exception as error:
    root = tk.Tk()
    root.withdraw()

    messagebox.showerror(
        "Model Loading Error",
        f"Could not load the AI model:\n{error}\n\n"
        "Please check that scam_model.pkl exists."
    )

    root.destroy()
    raise SystemExit


# ==========================================
# CREATE DATABASE
# ==========================================

try:
    create_database()
except Exception as error:
    root = tk.Tk()
    root.withdraw()

    messagebox.showerror(
        "Database Error",
        f"Could not initialize the database:\n{error}"
    )

    root.destroy()
    raise SystemExit


# ==========================================
# FIND SUSPICIOUS INDICATORS
# ==========================================

def find_warning_signs(message):

    warning_patterns = {
        "Requests for payment": [
            r"\bregistration fee\b",
            r"\bpay now\b",
            r"\bprocessing fee\b",
            r"\bupfront payment\b",
            r"\bsend money\b"
        ],

        "Prize or reward claims": [
            r"\bwon a prize\b",
            r"\bclaim your prize\b",
            r"\bwon a free prize\b",
            r"\bclaim your reward\b",
            r"\bcongratulations\b",
            r"\bfree gift\b"
        ],

        "Urgent language": [
            r"\bact now\b",
            r"\burgent\b",
            r"\bimmediately\b",
            r"\blimited time\b",
            r"\bwithin 24 hours\b"
        ],

        "Sensitive information requests": [
            r"\bbank details\b",
            r"\bpassword\b",
            r"\botp\b",
            r"\bpin number\b",
            r"\baccount details\b"
        ],

        "Suspicious link indicators": [
            r"https?://\S+",
            r"\bwww\.\S+",
            r"\bclick here\b"
        ]
    }

    found = []

    for category, patterns in warning_patterns.items():

        for pattern in patterns:

            if re.search(pattern, message, re.IGNORECASE):
                found.append(category)
                break

    return found


# ==========================================
# ANALYZE MESSAGE
# ==========================================

def analyze_message():

    message = message_box.get("1.0", tk.END).strip()

    if not message:

        messagebox.showwarning(
            "Empty Message",
            "Please enter a message to analyze."
        )

        return

    try:

        # AI prediction
        prediction = model.predict([message])[0]

        # Get prediction probabilities
        probabilities = model.predict_proba([message])[0]

        # Find spam probability
        spam_index = list(model.classes_).index("spam")

        spam_probability = float(
            probabilities[spam_index] * 100
        )

    except Exception as error:

        messagebox.showerror(
            "Prediction Error",
            f"Could not analyze the message:\n{error}"
        )

        return

    # Save analysis in the database
    try:

        save_history(
            message,
            "Spam" if prediction == "spam" else "Legitimate",
            spam_probability
        )

    except Exception as error:

        messagebox.showerror(
            "Database Error",
            f"Prediction completed, but history could not be saved:\n{error}"
        )

    # Display prediction
    if prediction == "spam":

        result_label.config(
            text="⚠ POTENTIAL SPAM MESSAGE",
            fg="#dc2626"
        )

    else:

        result_label.config(
            text="LIKELY LEGITIMATE MESSAGE",
            fg="#15803d"
        )

    # Display model-estimated spam probability
    probability_label.config(
        text=(
            "Model-estimated spam probability: "
            f"{spam_probability:.1f}%"
        )
    )

    # Find suspicious indicators
    warning_signs = find_warning_signs(message)

    warning_box.config(state="normal")
    warning_box.delete("1.0", tk.END)

    if warning_signs:

        warning_box.insert(
            tk.END,
            "\n".join("- " + sign for sign in warning_signs)
        )

    else:

        warning_box.insert(
            tk.END,
            "No predefined warning patterns detected."
        )

    warning_box.config(state="disabled")

    # Display disclaimer
    note_label.config(
        text=(
            "Warning signs are not proof of fraud. "
            "AI predictions may be incorrect."
        )
    )


# ==========================================
# VIEW DETECTION HISTORY
# ==========================================

def show_history():

    try:
        history = get_history()

    except Exception as error:

        messagebox.showerror(
            "History Error",
            f"Could not retrieve detection history:\n{error}"
        )

        return

    history_window = tk.Toplevel(root)

    history_window.title(
        "ScamShield AI - Detection History"
    )

    history_window.geometry("700x450")
    history_window.configure(bg="#f1f5f9")

    tk.Label(
        history_window,
        text="Detection History",
        font=("Arial", 18, "bold"),
        bg="#f1f5f9",
        fg="#1e3a8a"
    ).pack(pady=15)

    history_box = tk.Text(
        history_window,
        font=("Arial", 10),
        wrap="word",
        width=80,
        height=20
    )

    history_box.pack(
        padx=15,
        pady=10,
        fill="both",
        expand=True
    )

    if history:

        for message, prediction, confidence, analysis_time in history:

            history_box.insert(
                tk.END,
                f"Message: {message}\n"
                f"Prediction: {prediction}\n"
                f"Model-estimated spam probability: {confidence:.1f}%\n"
                f"Date: {analysis_time}\n"
                f"{'-' * 50}\n\n"
            )

    else:

        history_box.insert(
            tk.END,
            "No detection history available yet."
        )

    history_box.config(state="disabled")


# ==========================================
# VIEW DETECTION STATISTICS
# ==========================================

def show_statistics():

    try:

        total, spam, legitimate, spam_percentage = get_statistics()

    except Exception as error:

        messagebox.showerror(
            "Statistics Error",
            f"Could not retrieve detection statistics:\n{error}"
        )

        return

    stats_window = tk.Toplevel(root)

    stats_window.title(
        "ScamShield AI - Statistics"
    )

    stats_window.geometry("450x350")
    stats_window.configure(bg="#f1f5f9")

    tk.Label(
        stats_window,
        text="Detection Statistics",
        font=("Arial", 20, "bold"),
        bg="#f1f5f9",
        fg="#1e3a8a"
    ).pack(pady=20)

    tk.Label(
        stats_window,
        text=f"Total Messages Analyzed: {total}",
        font=("Arial", 13),
        bg="#f1f5f9"
    ).pack(pady=10)

    tk.Label(
        stats_window,
        text=f"Spam Messages: {spam}",
        font=("Arial", 13, "bold"),
        fg="#dc2626",
        bg="#f1f5f9"
    ).pack(pady=10)

    tk.Label(
        stats_window,
        text=f"Legitimate Messages: {legitimate}",
        font=("Arial", 13, "bold"),
        fg="#15803d",
        bg="#f1f5f9"
    ).pack(pady=10)

    tk.Label(
        stats_window,
        text=f"Spam Percentage: {spam_percentage:.1f}%",
        font=("Arial", 13, "bold"),
        bg="#f1f5f9"
    ).pack(pady=10)


# ==========================================
# CLEAR MESSAGE AND RESULTS
# ==========================================

def clear_message():

    message_box.delete("1.0", tk.END)

    result_label.config(text="")
    probability_label.config(text="")
    note_label.config(text="")

    warning_box.config(state="normal")
    warning_box.delete("1.0", tk.END)
    warning_box.config(state="disabled")


# ==========================================
# MAIN APPLICATION WINDOW
# ==========================================

root = tk.Tk()

root.title("ScamShield AI")
root.geometry("760x760")
root.minsize(650, 650)

# Original light background
root.configure(bg="#f1f5f9")


# ==========================================
# APPLICATION HEADING
# ==========================================

tk.Label(
    root,
    text="SCAMSHIELD AI",
    font=("Arial", 25, "bold"),
    bg="#f1f5f9",
    fg="#1e3a8a"
).pack(pady=(20, 5))


tk.Label(
    root,
    text="AI-Powered SMS Spam Detection System",
    font=("Arial", 12),
    bg="#f1f5f9",
    fg="#475569"
).pack(pady=(0, 20))


# ==========================================
# MESSAGE INPUT HEADING
# ==========================================

tk.Label(
    root,
    text="Enter your message:",
    font=("Arial", 12, "bold"),
    bg="#f1f5f9",
    fg="#1e293b"
).pack(anchor="w", padx=40)


# ==========================================
# MESSAGE INPUT BOX
# ==========================================

message_box = tk.Text(
    root,
    height=6,
    width=75,
    font=("Arial", 11),
    wrap="word",
    relief="solid",
    bd=1
)

message_box.pack(padx=35, pady=10)


# ==========================================
# ANALYZE BUTTON
# ==========================================

tk.Button(
    root,
    text="ANALYZE MESSAGE",
    command=analyze_message,
    font=("Arial", 12, "bold"),
    bg="#2563eb",
    fg="white",
    cursor="hand2",
    padx=15,
    pady=10
).pack(pady=8)


# ==========================================
# CLEAR BUTTON
# ==========================================

tk.Button(
    root,
    text="Clear",
    command=clear_message,
    font=("Arial", 10),
    cursor="hand2"
).pack(pady=3)


# ==========================================
# DETECTION HISTORY BUTTON
# ==========================================

tk.Button(
    root,
    text="View Detection History",
    command=show_history,
    font=("Arial", 10, "bold"),
    bg="#0f766e",
    fg="white",
    cursor="hand2",
    padx=10,
    pady=6
).pack(pady=5)


# ==========================================
# DETECTION STATISTICS BUTTON
# ==========================================

tk.Button(
    root,
    text="View Detection Statistics",
    command=show_statistics,
    font=("Arial", 10, "bold"),
    bg="#7c3aed",
    fg="white",
    cursor="hand2",
    padx=10,
    pady=6
).pack(pady=5)


# ==========================================
# PREDICTION RESULT
# ==========================================

result_label = tk.Label(
    root,
    text="",
    font=("Arial", 15, "bold"),
    bg="#f1f5f9"
)

result_label.pack(pady=(12, 5))


# ==========================================
# SPAM PROBABILITY
# ==========================================

probability_label = tk.Label(
    root,
    text="",
    font=("Arial", 11),
    bg="#f1f5f9",
    fg="#334155"
)

probability_label.pack(pady=5)


# ==========================================
# SUSPICIOUS INDICATORS HEADING
# ==========================================

tk.Label(
    root,
    text="Suspicious Indicators",
    font=("Arial", 12, "bold"),
    bg="#f1f5f9",
    fg="#1e293b"
).pack(pady=(10, 5))


# ==========================================
# SUSPICIOUS INDICATORS BOX
# ==========================================

warning_box = tk.Text(
    root,
    height=5,
    width=75,
    font=("Arial", 10),
    wrap="word",
    relief="solid",
    bd=1
)

warning_box.pack(padx=35, pady=5)
warning_box.config(state="disabled")


# ==========================================
# DISCLAIMER
# ==========================================

note_label = tk.Label(
    root,
    text="",
    font=("Arial", 9),
    bg="#f1f5f9",
    fg="#64748b",
    wraplength=680
)

note_label.pack(pady=8)


# ==========================================
# START APPLICATION
# ==========================================

root.mainloop()