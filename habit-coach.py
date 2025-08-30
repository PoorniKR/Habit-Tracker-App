import os
import hashlib
import binascii
import datetime as dt
from typing import Dict, List
import matplotlib.pyplot as plt
import streamlit as st
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, Float, Date, ForeignKey, UniqueConstraint
from sqlalchemy.orm import sessionmaker, declarative_base, relationship

try:
    from langchain_google_genai import ChatGoogleGenerativeAI
    from langchain_core.prompts import ChatPromptTemplate
    LLM_AVAILABLE = True
except Exception:
    LLM_AVAILABLE = False

# ---------------- Config ----------------
load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")  
DATABASE_URL = os.getenv("DATABASE_URL")     

# ---------------- Database ----------------
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    display_name = Column(String, nullable=False)
    salt = Column(String, nullable=False)
    pwdhash = Column(String, nullable=False)
    habits = relationship("Habit", back_populates="user")

class Habit(Base):
    __tablename__ = "habits"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    name = Column(String, nullable=False)   # internal key
    label = Column(String, nullable=False)  # display
    type = Column(String, nullable=False)   # int or float
    target = Column(Float, nullable=True)
    user = relationship("User", back_populates="habits")
    logs = relationship("HabitLog", back_populates="habit")

class HabitLog(Base):
    __tablename__ = "habit_logs"
    id = Column(Integer, primary_key=True)
    habit_id = Column(Integer, ForeignKey("habits.id"))
    date = Column(Date, nullable=False)
    value = Column(Float, nullable=True)
    habit = relationship("Habit", back_populates="logs")
    __table_args__ = (UniqueConstraint("habit_id", "date", name="_habit_date_uc"),)

# DB engine + session
engine = create_engine(DATABASE_URL, echo=False)
Base.metadata.create_all(engine)
SessionLocal = sessionmaker(bind=engine)

# ---------------- Security helpers ----------------
def hash_password(password: str, salt: bytes = None) -> Dict[str, str]:
    if salt is None:
        salt = os.urandom(16)
    pwdhash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return {"salt": binascii.hexlify(salt).decode(), "pwdhash": binascii.hexlify(pwdhash).decode()}

def verify_password(stored: Dict[str, str], provided_password: str) -> bool:
    salt = binascii.unhexlify(stored["salt"].encode())
    expected_hash = stored["pwdhash"]
    test = hashlib.pbkdf2_hmac("sha256", provided_password.encode("utf-8"), salt, 200_000)
    return binascii.hexlify(test).decode() == expected_hash

# ---------------- User helpers ----------------
def register_user(username: str, password: str, display_name: str) -> bool:
    db = SessionLocal()
    if db.query(User).filter_by(username=username).first():
        db.close()
        return False

    h = hash_password(password)
    user = User(username=username, display_name=display_name, salt=h["salt"], pwdhash=h["pwdhash"])
    db.add(user)
    db.commit()

    # Insert default habits into DB for this new user
    defaults = {
        "sleep": {"label": "Sleep (hours)", "type": "float", "target": 8},
        "steps": {"label": "Steps", "type": "int", "target": 8000},
        "water": {"label": "Water (glasses)", "type": "int", "target": 8},
    }
    for key, meta in defaults.items():
        habit = Habit(user_id=user.id, name=key, label=meta["label"], type=meta["type"], target=meta["target"])
        db.add(habit)

    db.commit()
    db.close()
    return True

def login_user(username: str, password: str) -> bool:
    db = SessionLocal()
    user = db.query(User).filter_by(username=username).first()
    db.close()
    if not user:
        return False
    return verify_password({"salt": user.salt, "pwdhash": user.pwdhash}, password)

def get_user(username: str):
    db = SessionLocal()
    user = db.query(User).filter_by(username=username).first()
    db.close()
    return user

# ---------------- Habit helpers ----------------
def load_habits(username: str) -> Dict[str, Dict]:
    db = SessionLocal()
    user = db.query(User).filter_by(username=username).first()
    if not user:
        db.close()
        return {}
    habits = {h.name: {"label": h.label, "type": h.type, "target": h.target} for h in user.habits}
    db.close()
    if not habits:
        # default habits (first-time users)
        return {
            "sleep": {"label": "Sleep (hours)", "type": "float", "target": 8},
            "steps": {"label": "Steps", "type": "int", "target": 8000},
            "water": {"label": "Water (glasses)", "type": "int", "target": 8},
        }
    return habits

def save_habit(username: str, key: str, label: str, htype: str, target: float):
    db = SessionLocal()
    user = db.query(User).filter_by(username=username).first()
    habit = db.query(Habit).filter_by(user_id=user.id, name=key).first()
    if not habit:
        habit = Habit(user_id=user.id, name=key, label=label, type=htype, target=target)
        db.add(habit)
    else:
        habit.label = label
        habit.type = htype
        habit.target = target
    db.commit()
    db.close()

def delete_habit(username: str, key: str):
    db = SessionLocal()
    user = db.query(User).filter_by(username=username).first()
    habit = db.query(Habit).filter_by(user_id=user.id, name=key).first()
    if habit:
        db.delete(habit)
        db.commit()
    db.close()

# ---------------- Logs ----------------
def load_user_logs(username: str) -> List[Dict[str, str]]:
    db = SessionLocal()
    user = db.query(User).filter_by(username=username).first()
    if not user:
        db.close()
        return []
    rows = []
    for habit in user.habits:
        for log in habit.logs:
            rows.append({"date": log.date.isoformat(), habit.name: log.value})
    db.close()
    # merge by date
    merged = {}
    for r in rows:
        d = r["date"]
        if d not in merged:
            merged[d] = {"date": d}
        merged[d].update(r)
    return sorted(list(merged.values()), key=lambda x: x["date"])

def save_user_logs(username: str, habit_values: Dict[str, float]):
    db = SessionLocal()
    user = db.query(User).filter_by(username=username).first()
    today = dt.date.today()
    for key, val in habit_values.items():
        habit = db.query(Habit).filter_by(user_id=user.id, name=key).first()
        if not habit:
            continue
        log = db.query(HabitLog).filter_by(habit_id=habit.id, date=today).first()
        if not log:
            log = HabitLog(habit_id=habit.id, date=today, value=val)
            db.add(log)
        else:
            log.value = val
    db.commit()
    db.close()

# ---------------- LLM helper ----------------
def llm_feedback(username: str, rows: List[Dict[str, str]]) -> str:
    if not LLM_AVAILABLE or not GEMINI_API_KEY:
        return "AI feedback not available (missing dependencies or GEMINI_API_KEY)."
    last_logs = rows[-14:]
    habits = load_habits(username)
    habits_text = "\n".join([str(r) for r in last_logs])
    targets_text = "\n".join([f"{k}: {v.get('target')} ({v.get('label')})" for k,v in habits.items()])
    prompt = ChatPromptTemplate.from_template(
        """
        You are an expert personal habit coach with motivational psychology expertise.
        Analyze the last 5 days of data.

        ### Targets
        {targets_text}

        ### Logs
        {habits_text}

        Provide:
        1. Overall summary
        2. Strongest habit
        3. Weakest habit + why
        """
    )

        #     4. Trend per habit
        # 5. One small SMART goal for tomorrow
        # 6. End with motivational cheer (under 200 words).
    llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash", google_api_key=GEMINI_API_KEY)
    chain = prompt | llm
    result = chain.invoke({"habits_text": habits_text, "targets_text": targets_text})
    return result.content

# ---------------- Streamlit UI ----------------
st.set_page_config(page_title="Personal Habit Coach", layout="centered")
st.title("📝 Personal Habit Coach")

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""
if "display" not in st.session_state:
    st.session_state.display = ""
if "auth_page" not in st.session_state:
    st.session_state.auth_page = "login"

# ---------------- AUTH ----------------
if not st.session_state.logged_in:   # instead of username is None
    if st.session_state.auth_page == "login":
        st.header("🔑 Login")
        login_user_input = st.text_input("Username")
        login_pwd = st.text_input("Password", type="password")
        if st.button("Login"):
            if login_user(login_user_input.strip(), login_pwd):
                user = get_user(login_user_input.strip())
                st.session_state.username = user.username
                st.session_state.display = user.display_name
                st.session_state.logged_in = True
                st.success(f"Welcome back, {user.display_name}! 🎉")
                st.rerun()
            else:
                st.error("Invalid username or password.")
        if st.button("Go to Sign up"):
            st.session_state.auth_page = "signup"
            st.rerun()

    elif st.session_state.auth_page == "signup":
        st.header("🆕 Sign Up")
        su_user = st.text_input("Choose username")
        su_name = st.text_input("Your display name")
        su_pwd = st.text_input("Choose password", type="password")
        if st.button("Sign up"):
            if register_user(su_user.strip(), su_pwd, su_name.strip() or su_user.strip()):
                st.success("✅ Registered! Please log in.")
                st.session_state.auth_page = "login"
                st.rerun()
            else:
                st.error("Username already exists.")
        if st.button("Back to Login"):
            st.session_state.auth_page = "login"
            st.rerun()

    st.stop()


# ---------------- MAIN APP ----------------
username = st.session_state.username
display = st.session_state.display or username
st.sidebar.write(f"👋 Signed in as **{display}**")
if st.sidebar.button("Logout"):
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.display = ""
    st.success("You have been logged out ✅")
    st.rerun()

habits = load_habits(username)
rows = load_user_logs(username)

st.sidebar.header("Navigation")
page = st.sidebar.radio("Go to", ["Dashboard", "Log Habits", "Manage Habits", "View Data", "AI Feedback"])

if page == "Dashboard":
    st.header("📊 Dashboard")
    if not rows:
        st.info("No data yet.")
    else:
        last7 = rows[-7:]
        for key, meta in habits.items():
            vals = []
            for r in last7:
                try: vals.append(float(r.get(key)))
                except: pass
            if vals:
                avg = sum(vals) / len(vals)
                t = meta.get("target")
                status = "Good job! 🎯" if t and avg >= t else f"Try {max(0, t-avg):.1f} more"
                st.write(f"- {meta['label']}: avg {avg:.1f} (target {t}) → {status}")

        # ✅ Single combined plot
        st.subheader("📈 Trends (all habits)")
        dates = [r["date"] for r in rows]
        plt.figure(figsize=(10, 5))

        for key, meta in habits.items():
            values = [float(r.get(key)) if r.get(key) else None for r in rows]
            xs, ys = [], []
            for d,v in zip(dates, values):
                if v is not None:
                    xs.append(d)
                    ys.append(v)
            if xs:
                plt.plot(xs, ys, marker="o", label=meta["label"])
                if meta.get("target"):
                    plt.axhline(meta["target"], linestyle="--", alpha=0.5)

        plt.legend()
        plt.xticks(rotation=45)
        plt.tight_layout()
        st.pyplot(plt)

elif page == "Log Habits":
    st.header("📝 Log today's habits")
    habit_values = {}
    with st.form("log_form"):
        for key, meta in habits.items():
            if meta["type"] == "int":
                step = 1000 if key=="steps" else 1
                habit_values[key] = st.number_input(meta["label"], min_value=0, step=step, key=f"log_{key}")
            else:
                habit_values[key] = st.number_input(meta["label"], min_value=0.0, step=0.1, key=f"log_{key}")
        submitted = st.form_submit_button("Save")
        if submitted:
            save_user_logs(username, habit_values)
            st.success("Saved today's habits ✅")

elif page == "Manage Habits":
    st.header("⚙️ Manage your habits")
    with st.form("manage_form"):
        new_name = st.text_input("New habit key (id)")
        new_label = st.text_input("Label (shown)")
        new_type = st.selectbox("Type", ["int","float"])
        new_target = st.number_input("Target (optional)", value=0.0, step=1.0)
        add = st.form_submit_button("Add habit")
        if add:
            save_habit(username, new_name.strip(), new_label or new_name, new_type, float(new_target))
            st.success(f"Added habit '{new_name}'.")
            st.rerun()
    for key, meta in habits.items():
        cols = st.columns([4,2,1])
        cols[0].markdown(f"**{key}** — {meta['label']}")
        cols[1].write(f"target: {meta['target']}")
        if cols[2].button(f"Remove {key}", key=f"rm_{key}"):
            delete_habit(username, key)
            st.success(f"Removed {key}")
            st.rerun()

elif page == "View Data":
    st.header("📂 Your logged data")
    st.dataframe(rows if rows else [])

elif page == "AI Feedback":
    st.header("🤖 AI Feedback")
    if not rows:
        st.info("No data yet.")
    elif st.button("Generate AI feedback"):
        with st.spinner("Thinking..."):
            out = llm_feedback(username, rows)
            st.write(out)
