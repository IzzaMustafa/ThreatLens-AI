import streamlit as st

from sources import analyze_target


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="ThreatLens AI",
    page_icon="🛡️",
    layout="centered"
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>

    .title {
        text-align: center;
        font-size: 42px;
        font-weight: 700;
        margin-bottom: 5px;
    }

    .subtitle {
        text-align: center;
        color: #777;
        font-size: 17px;
        margin-bottom: 30px;
    }

    .risk-box {
        padding: 20px;
        border-radius: 12px;
        border: 1px solid #ddd;
        text-align: center;
        margin-top: 10px;
        margin-bottom: 20px;
    }

    .risk-number {
        font-size: 46px;
        font-weight: 700;
    }

    .risk-label {
        font-size: 18px;
        color: #777;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="title">🛡️ ThreatLens AI</div>',
    unsafe_allow_html=True
)

st.markdown(
    """
    <div class="subtitle">
    AI-powered analysis of URLs, domains and IP addresses
    using threat intelligence and AI.
    </div>
    """,
    unsafe_allow_html=True
)


# ============================================================
# INPUT SECTION
# ============================================================

st.subheader("🔍 Analyze a Target")

input_type = st.selectbox(
    "Input Type",
    [
        "Domain",
        "URL",
        "IP Address"
    ]
)


# ============================================================
# DYNAMIC INPUT
# ============================================================

if input_type == "Domain":

    placeholder = "example.com"

elif input_type == "URL":

    placeholder = "https://example.com"

else:

    placeholder = "8.8.8.8"


target = st.text_input(
    f"Enter {input_type}",
    placeholder=placeholder
)


# ============================================================
# KNOWLEDGE LEVEL
# ============================================================

knowledge_level = st.selectbox(
    "Knowledge Level",
    [
        "Beginner",
        "Intermediate",
        "Advanced"
    ]
)


# ============================================================
# BUTTONS
# ============================================================

col1, col2 = st.columns(2)

with col1:

    analyze_button = st.button(
        "🔎 Analyze",
        use_container_width=True,
        type="primary"
    )

with col2:

    clear_button = st.button(
        "↺ Clear",
        use_container_width=True
    )


if clear_button:

    st.rerun()


# ============================================================
# ANALYSIS
# ============================================================

if analyze_button:

    if not target.strip():

        st.warning(
            f"Please enter a {input_type.lower()}."
        )

    else:

        with st.spinner(
            "Analyzing the target..."
        ):

            result = analyze_target(
                input_type,
                target.strip(),
                knowledge_level
            )


        if not result["success"]:

            st.error(
                result["message"]
            )

        else:

            st.success(
                "Analysis completed."
            )


            # =================================================
            # THREAT ASSESSMENT
            # =================================================

            risk = result["risk"]

            st.subheader(
                "🛡️ Threat Assessment"
            )

            score = risk["score"]
            verdict = risk["verdict"]
            confidence = risk["confidence"]


            # -------------------------------------------------
            # RISK SCORE
            # -------------------------------------------------

            if score is not None:

                st.markdown(
                    f"""
                    <div class="risk-box">

                    <div class="risk-number">
                    {score}%
                    </div>

                    <div class="risk-label">
                    Risk Score
                    </div>

                    </div>
                    """,
                    unsafe_allow_html=True
                )

                st.progress(
                    score / 100
                )

            else:

                st.info(
                    "A risk score could not be determined."
                )


            # -------------------------------------------------
            # VERDICT + CONFIDENCE
            # -------------------------------------------------

            col1, col2 = st.columns(2)

            with col1:

                st.metric(
                    "Assessment",
                    verdict
                )

            with col2:

                st.metric(
                    "Confidence",
                    confidence
                )


            # =================================================
            # AI SUMMARY
            # =================================================

            st.subheader(
                "🤖 What does this mean?"
            )

            gemini = result["gemini"]


            if gemini["success"]:

                analysis = gemini["analysis"]


                # ------------------------------------------------
                # SIMPLE SUMMARY
                # ------------------------------------------------

                summary = analysis.get(
                    "summary",
                    "No summary was generated."
                )

                st.write(
                    summary
                )


                # ------------------------------------------------
                # REASONS
                # ------------------------------------------------

                reasons = analysis.get(
                    "reasons",
                    []
                )

                if reasons:

                    st.markdown(
                        "**Why?**"
                    )

                    for reason in reasons:

                        st.write(
                            f"• {reason}"
                        )


                # ------------------------------------------------
                # RECOMMENDATION
                # ------------------------------------------------

                recommendation = analysis.get(
                    "recommendation",
                    ""
                )

                if recommendation:

                    st.info(
                        f"💡 {recommendation}"
                    )


            else:

                st.error(
                    f"AI analysis error: {gemini.get('message', 'Unknown error')}"
                )


            # =================================================
            # VIRUSTOTAL DETAILS
            # =================================================

            with st.expander(
                "🧪 VirusTotal Details"
            ):

                vt = result["virustotal"]

                if vt["success"]:

                    malicious = vt["malicious"]
                    suspicious = vt["suspicious"]
                    harmless = vt["harmless"]
                    undetected = vt["undetected"]

                    total = (
                        malicious
                        + suspicious
                        + harmless
                        + undetected
                    )


                    # --------------------------------------------
                    # DETECTION COUNTS
                    # --------------------------------------------

                    col1, col2, col3, col4 = st.columns(4)

                    col1.metric(
                        "Malicious",
                        malicious
                    )

                    col2.metric(
                        "Suspicious",
                        suspicious
                    )

                    col3.metric(
                        "Harmless",
                        harmless
                    )

                    col4.metric(
                        "Undetected",
                        undetected
                    )


                    # --------------------------------------------
                    # PERCENTAGES
                    # --------------------------------------------

                    if total > 0:

                        st.markdown(
                            "**Detection Statistics**"
                        )

                        st.write(
                            f"Malicious: "
                            f"**{(malicious / total) * 100:.1f}%**"
                        )

                        st.write(
                            f"Suspicious: "
                            f"**{(suspicious / total) * 100:.1f}%**"
                        )

                        st.write(
                            f"Harmless: "
                            f"**{(harmless / total) * 100:.1f}%**"
                        )

                        st.write(
                            f"Undetected: "
                            f"**{(undetected / total) * 100:.1f}%**"
                        )


                    st.write(
                        f"**VirusTotal Reputation:** "
                        f"`{vt['reputation']}`"
                    )

                else:

                    st.info(
                        vt["message"]
                    )


            # =================================================
            # WHOIS DETAILS
            # =================================================

            with st.expander(
                "🌐 WHOIS Details"
            ):

                whois_data = result["whois"]

                if whois_data["success"]:

                    st.write(
                        f"**Domain / Host:** "
                        f"{whois_data['domain']}"
                    )

                    st.write(
                        f"**Registrar:** "
                        f"{whois_data['registrar']}"
                    )

                    st.write(
                        f"**Created:** "
                        f"{whois_data['creation_date']}"
                    )

                    st.write(
                        f"**Expires:** "
                        f"{whois_data['expiration_date']}"
                    )


                    if whois_data["name_servers"]:

                        st.write(
                            "**Name Servers:**"
                        )

                        for server in whois_data[
                            "name_servers"
                        ]:

                            st.write(
                                f"• {server}"
                            )

                else:

                    st.info(
                        whois_data["message"]
                    )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "ThreatLens AI provides an automated risk assessment "
    "for informational purposes. A clean result does not "
    "guarantee that a URL, domain, or IP address is safe."
)
