# app.py
import os
import requests
import streamlit as st
import firebase_admin
from firebase_admin import credentials, firestore, auth, storage as fb_storage
from google.cloud import storage as gcs

# ---------------------------
# CONFIG
# ---------------------------
# Required secrets (all flat keys; NO secrets.toml file needed):
# st.secrets["apiKey"]                 -> Firebase Web API key
# st.secrets["project_id"]              -> Firebase project ID
# Optional: st.secrets["storage_bucket"] (defaults to "<project_id>.appspot.com")
#
# Service account (flat, exactly like your format):
# st.secrets["type"], ["project_id"], ["private_key_id"], ["private_key"],
# ["client_email"], ["client_id"], ["auth_uri"], ["token_uri"],
# ["auth_provider_x509_cert_url"], ["client_x509_cert_url"], ["universe_domain"]

FIREBASE_REST_SIGNIN = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key="


# ---------------------------
# FIREBASE INIT (your format)
# ---------------------------
def initialize_firebase():
    try:
        # Some deployments store private_key with literal '\n' — fix if needed.
        private_key = st.secrets["private_key"]
        if "\\n" in private_key:
            private_key = private_key.replace("\\n", "\n")

        cred = credentials.Certificate({
            "type": st.secrets["type"],
            "project_id": st.secrets["project_id"],
            "private_key_id": st.secrets["private_key_id"],
            "private_key": private_key,
            "client_email": st.secrets["client_email"],
            "client_id": st.secrets["client_id"],
            "auth_uri": st.secrets["auth_uri"],
            "token_uri": st.secrets["token_uri"],
            "auth_provider_x509_cert_url": st.secrets["auth_provider_x509_cert_url"],
            "client_x509_cert_url": st.secrets["client_x509_cert_url"],
            "universe_domain": st.secrets.get("universe_domain", "googleapis.com"),
        })

        storage_bucket = st.secrets.get(
            "storage_bucket",
            f"{st.secrets['project_id']}.appspot.com"
        )

        if not firebase_admin._apps:
            firebase_admin.initialize_app(cred, {"storageBucket": storage_bucket})

        db = firestore.client()
        bucket = fb_storage.bucket()  # uses the default set above
        return db, bucket
    except Exception as e:
        st.error(f"❌ Firebase initialization failed: {e}")
        raise


db, bucket = initialize_firebase()


# ---------------------------
# HELPERS
# ---------------------------
def signin_email_password(email: str, password: str):
    """Sign in via Firebase Auth REST; returns JSON with localId(uid), idToken, email."""
    apiKey = st.secrets["apiKey"]
    url = FIREBASE_REST_SIGNIN + apiKey
    payload = {"email": email, "password": password, "returnSecureToken": True}
    r = requests.post(url, json=payload, timeout=10)
    r.raise_for_status()
    return r.json()


def _batch_delete_collection(collection_ref, batch_size=500):
    """Delete all docs in a (sub)collection in batches."""
    docs = list(collection_ref.limit(batch_size).stream())
    while docs:
        batch = db.batch()
        for d in docs:
            batch.delete(d.reference)
        batch.commit()

        # paginate properly using the last doc snapshot
        last_doc = docs[-1]
        docs = list(
            collection_ref.start_after(last_doc).limit(batch_size).stream()
        )


def delete_user_firestore(uid: str):
    """Delete user root doc and all its subcollections under Users/{uid}."""
    user_ref = db.collection("Users").document(uid)  # <-- use .document() not .doc()

    # Delete all subcollections dynamically
    for col in user_ref.collections():
        _batch_delete_collection(col, batch_size=500)

    # Delete the root user doc (ignore if missing)
    try:
        user_ref.delete()
    except Exception:
        pass



def delete_user_storage(uid: str):
    """Best-effort remove all files under users/{uid}/ in Cloud Storage."""
    try:
        client = gcs.Client(project=st.secrets["project_id"])
        b = client.bucket(bucket.name)
        for blob in client.list_blobs(b.name, prefix=f"users/{uid}/"):
            try:
                b.blob(blob.name).delete()
            except Exception:
                pass
    except Exception:
        # Don’t block the account deletion on storage hiccups
        pass


def hard_delete_user(uid: str):
    """Delete Firestore data, Storage files, and the Auth user."""
    delete_user_firestore(uid)
    delete_user_storage(uid)
    try:
        auth.delete_user(uid)
    except auth.UserNotFoundError:
        pass


# ---------------------------
# UI (red/white, sleek)
# ---------------------------
st.set_page_config(page_title="Delete Account – BabyCue", page_icon="🗑️", layout="centered")

# Red gradient header
st.markdown(
    """
    <div style="height:170px;background:linear-gradient(135deg,#e53935,#ff5a4f);
    border-bottom-left-radius:28px;border-bottom-right-radius:28px;"></div>
    """,
    unsafe_allow_html=True,
)
st.markdown("<h2 style='margin-top:-110px;'>Delete your Gi-Bud account</h2>", unsafe_allow_html=True)

card_css = """
<div style="border:1px solid #f3c9cd;border-radius:16px;
box-shadow:0 14px 36px rgba(229,57,53,.12);padding:18px;">
{inner}
</div>
"""

# Auth card
st.markdown(card_css.format(inner="""
<b>Step 1 — Sign in</b> with the account you want to delete.
"""), unsafe_allow_html=True)

email = st.text_input("Email", placeholder="you@example.com")
password = st.text_input("Password", type="password", placeholder="••••••••")

if "auth" not in st.session_state:
    st.session_state.auth = None

col1, col2 = st.columns(2)
with col1:
    if st.button("Sign in with Email & Password", use_container_width=True):
        try:
            data = signin_email_password(email.strip(), password)
            st.session_state.auth = {"uid": data["localId"], "email": data["email"]}
            st.success("Signed in successfully.")
        except requests.HTTPError as e:
            err = e.response.json().get("error", {}).get("message", "SIGNIN_FAILED")
            st.error(f"Sign-in failed: {err}")
with col2:
    if st.button("Sign out", use_container_width=True):
        st.session_state.auth = None
        st.info("Signed out.")

st.markdown("---")

# Delete card
if st.session_state.auth:
    st.info(f"Signed in as **{st.session_state.auth['email']}** (uid: `{st.session_state.auth['uid']}`)")

    st.markdown(card_css.format(inner="""
<b>Step 2 — Review consequences</b>
<ul style="line-height:1.6; margin-top:8px;">
  <li>All profile data and preferences will be removed.</li>
  <li>All survey reports/history and uploaded files/images will be permanently deleted.</li>
  <li>This action is irreversible. Limited data may be retained only if required by law (e.g., fraud prevention).</li>
</ul>
"""), unsafe_allow_html=True)

    confirm = st.checkbox("I understand and want to permanently delete my account.")

    delete_btn = st.button("Delete my account", type="primary", disabled=not confirm, use_container_width=True)
    if delete_btn:
        try:
            uid = st.session_state.auth["uid"]
            hard_delete_user(uid)
            st.session_state.auth = None
            st.session_state.deleted = True   # 👈 add this flag
            st.success("Account deleted. We’re sorry to see you go.")
        except Exception as e:
            st.error(f"Deletion error: {e}")
    if st.session_state.get("deleted", False):
        st.markdown(card_css.format(inner="""
    <div style="text-align:center;">
      <h3 style="color:#e53935; margin-bottom:6px;">✅ Account Deleted</h3>
      <p style="color:#444;">Your Gi-Bud account and all associated data have been permanently removed.</p>
      <p style="color:#777; font-size:13px;">We’re sorry to see you go. If you change your mind, you’re always welcome to sign up again!</p>
    </div>
    """), unsafe_allow_html=True)    
else:
    st.warning("Please sign in to continue.")

    