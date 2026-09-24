import sys
from pathlib import Path

import streamlit as st


# --------------------------------------------------
# PROJECT ROOT
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from app.pipeline import run_pipeline


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="SENTRY SOC",
    page_icon="🛡️",
    layout="wide"
)


# --------------------------------------------------
# LOAD SENTRY DATA
# --------------------------------------------------

results = run_pipeline()

events = results["events"]
alerts = results["alerts"]
correlations = results["correlations"]
incidents = results["incidents"]


# --------------------------------------------------
# HEADER
# --------------------------------------------------

st.title("🛡️ SENTRY SOC")
st.caption(
    "Security Event Detection & Threat Investigation Platform"
)

st.divider()


# --------------------------------------------------
# TOP METRICS
# --------------------------------------------------

total_events = len(events)
total_alerts = len(alerts)
total_incidents = len(incidents)

if incidents:
    highest_risk = max(
        incidents,
        key=lambda incident: incident["risk_score"]
    )

    risk_score = highest_risk["risk_score"]
    risk_level = highest_risk["risk_level"].upper()
else:
    risk_score = 0
    risk_level = "LOW"


col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Events", total_events)

with col2:
    st.metric("Alerts", total_alerts)

with col3:
    st.metric("Incidents", total_incidents)

with col4:
    st.metric(
        "Highest Risk",
        f"{risk_score} / {risk_level}"
    )


st.divider()


# --------------------------------------------------
# ACTIVE INCIDENTS
# --------------------------------------------------

st.subheader("🚨 Active Incidents")

if not incidents:

    st.success("No active incidents detected.")

else:

    for incident in incidents:

        with st.container(border=True):

            col1, col2, col3 = st.columns([2, 2, 1])

            with col1:

                st.markdown(
                    f"### {incident['incident_id']}"
                )

                st.write(
                    incident["type"]
                    .replace("_", " ")
                    .title()
                )

            with col2:

                st.write(
                    f"**Source IP:** "
                    f"{incident['source_ip']}"
                )

                st.write(
                    f"**Username:** "
                    f"{incident['username']}"
                )

            with col3:

                st.metric(
                    "Risk",
                    incident["risk_score"]
                )

                st.write(
                    f"**{incident['risk_level'].upper()}**"
                )


st.divider()


# --------------------------------------------------
# INCIDENT INVESTIGATION
# --------------------------------------------------

st.subheader("🔍 Incident Investigation")

if not incidents:

    st.info("No incidents available for investigation.")

else:

    incident_options = [
        incident["incident_id"]
        for incident in incidents
    ]

    selected_incident_id = st.selectbox(
        "Select an incident",
        incident_options
    )

    selected_incident = next(
        incident
        for incident in incidents
        if incident["incident_id"] == selected_incident_id
    )

    st.markdown(
        f"### {selected_incident['incident_id']} — "
        f"{selected_incident['type'].replace('_', ' ').title()}"
    )

    # ----------------------------------------------
    # INCIDENT SUMMARY
    # ----------------------------------------------

    summary_col1, summary_col2, summary_col3, summary_col4 = (
        st.columns(4)
    )

    with summary_col1:
        st.metric(
            "Risk Score",
            selected_incident["risk_score"]
        )

    with summary_col2:
        st.metric(
            "Risk Level",
            selected_incident["risk_level"].upper()
        )

    with summary_col3:
        st.metric(
            "Related Events",
            selected_incident["related_events"]
        )

    with summary_col4:
        st.metric(
            "Status",
            selected_incident["status"].upper()
        )

    # ----------------------------------------------
    # INCIDENT DETAILS
    # ----------------------------------------------

    detail_col1, detail_col2 = st.columns(2)

    with detail_col1:

        st.markdown("#### 🎯 Incident Details")

        st.write(
            f"**Source IP:** "
            f"{selected_incident['source_ip']}"
        )

        st.write(
            f"**Username:** "
            f"{selected_incident['username']}"
        )

        st.write(
            f"**Incident Type:** "
            f"{selected_incident['type'].replace('_', ' ').title()}"
        )

    with detail_col2:

        st.markdown("#### 🧾 Evidence")

        evidence = selected_incident["evidence"]

        st.write(
            f"**Correlation ID:** "
            f"{evidence['correlation_id']}"
        )

        st.write(
            f"**Event Count:** "
            f"{evidence['event_count']}"
        )

        st.write(
            f"**Time Window:** "
            f"{evidence['time_window_seconds']} seconds"
        )

    # ----------------------------------------------
    # WHY FLAGGED
    # ----------------------------------------------

    st.markdown("#### 💡 Why was this incident created?")

    st.info(
        selected_incident["evidence"]["reason"]
    )

    # ----------------------------------------------
    # TIMELINE
    # ----------------------------------------------

    st.markdown("#### 🕒 Investigation Timeline")

    incident_timestamps = selected_incident["timeline"]

    for timestamp in incident_timestamps:

        matching_events = [
            event
            for event in events
            if event["timestamp"] == timestamp
        ]

        if matching_events:

            event = matching_events[0]

            st.write(
                f"**{event['timestamp']}** — "
                f"{event['event']}"
            )

            st.caption(
                f"Source IP: {event['source_ip']} | "
                f"Username: {event['username']} | "
                f"Level: {event['level']}"
            )

    # ----------------------------------------------
    # RELATED ALERTS
    # ----------------------------------------------

    st.markdown("#### 🚨 Related Alerts")

    related_alerts = [
        alert
        for alert in alerts
        if alert["event"]["source_ip"]
        == selected_incident["source_ip"]
    ]

    for alert in related_alerts:

        st.write(
            f"**{alert['detection']['rule_id']}** — "
            f"{alert['event']['event']} "
            f"(Risk {alert['risk']['risk_score']})"
        )


st.divider()


# --------------------------------------------------
# SECURITY ALERTS
# --------------------------------------------------

st.subheader("🚨 Security Alerts")

if not alerts:

    st.info("No security alerts generated.")

else:

    for alert in alerts:

        detection = alert["detection"]
        event = alert["event"]
        risk = alert["risk"]

        with st.expander(
            f"{detection['rule_id']} — "
            f"{event['event']}"
        ):

            col1, col2 = st.columns(2)

            with col1:

                st.write(
                    f"**Severity:** "
                    f"{detection['severity'].upper()}"
                )

                st.write(
                    f"**Risk Score:** "
                    f"{risk['risk_score']}"
                )

                st.write(
                    f"**Risk Level:** "
                    f"{risk['risk_level'].upper()}"
                )

            with col2:

                st.write(
                    f"**Source IP:** "
                    f"{event['source_ip']}"
                )

                st.write(
                    f"**Username:** "
                    f"{event['username']}"
                )

                st.write(
                    f"**Timestamp:** "
                    f"{event['timestamp']}"
                )

            st.markdown("**Why was this flagged?**")

            st.info(
                detection["reason"]
            )


st.divider()


# --------------------------------------------------
# CORRELATIONS
# --------------------------------------------------

st.subheader("🔗 Detected Correlations")

if not correlations:

    st.info("No event correlations detected.")

else:

    for correlation in correlations:

        with st.container(border=True):

            st.write(
                f"**{correlation['correlation_id']}**"
            )

            correlation_type = (
                correlation["type"]
                .replace("_", " ")
                .title()
            )

            st.write(
                f"**Type:** {correlation_type}"
            )

            st.write(
                f"**Source IP:** "
                f"{correlation['source_ip']}"
            )

            st.write(
                f"**Events:** "
                f"{correlation['event_count']}"
            )

            st.write(
                f"**Time Window:** "
                f"{correlation['time_window_seconds']} seconds"
            )

            st.info(
                correlation["reason"]
            )


st.divider()


# --------------------------------------------------
# SECURITY EVENTS
# --------------------------------------------------

st.subheader("📋 Security Events")

for event in events:

    st.write(
        f"**{event['timestamp']}** — "
        f"{event['event']} "
        f"({event['source_ip']})"
    )


st.divider()


# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.caption(
    "SENTRY — Security Event Detection & Threat Investigation Platform"
)