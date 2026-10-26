import json
from pathlib import Path

import pandas as pd
import streamlit as st

LOG = Path("logs/cowrie.json")

st.set_page_config(page_title="SSH Honeypot Dashboard", layout="wide")
st.title("SSH Honeypot Dashboard (Cowrie)")
st.caption("Traffic generated in an isolated lab to test the logging and analysis pipeline.")


@st.cache_data
def load(path):
    rows = []
    with open(path) as f:
        for line in f:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    df = pd.DataFrame(rows)
    for col in ("username", "password", "input", "src_ip"):
        if col not in df.columns:
            df[col] = None
    return df


if not LOG.exists():
    st.error("logs/cowrie.json not found. Run this from the project folder.")
    st.stop()

df = load(LOG)

sessions = df[df.eventid == "cowrie.session.connect"]
logins = df[df.eventid.str.startswith("cowrie.login", na=False) & df["password"].notna()]
cmds = (
    df[df.eventid == "cowrie.command.input"]["input"]
    .dropna().str.split(";").explode().str.strip()
)
cmds = cmds[(cmds != "") & (cmds != "exit")]

c1, c2, c3, c4 = st.columns(4)
c1.metric("Sessions", len(sessions))
c2.metric("Login attempts", len(logins))
c3.metric("Unique usernames", logins["username"].nunique())
c4.metric("Commands run", len(cmds))

left, right = st.columns(2)
with left:
    st.subheader("Top usernames")
    st.bar_chart(logins["username"].value_counts().head(10))
    st.subheader("Top commands")
    st.bar_chart(cmds.value_counts().head(10))
with right:
    st.subheader("Top passwords")
    st.bar_chart(logins["password"].value_counts().head(10))
    st.subheader("Sessions over time (per minute)")
    ts = pd.to_datetime(sessions["timestamp"]).dt.floor("min")
    st.bar_chart(ts.value_counts().sort_index())

with st.expander("Raw events (last 50)"):
    st.dataframe(df.tail(50))
