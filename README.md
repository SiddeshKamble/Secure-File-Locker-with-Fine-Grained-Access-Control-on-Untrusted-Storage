
Secure File Locker with Fine-Grained Access Control
---------------------------------------------------

This is a submission bundle for CIS 628 project.

Run the Streamlit UI:
1. Create a virtualenv and install dependencies:
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
2. Initialize DB (optional; Streamlit will initialize on first run):
   python3 -c "from src.db import init_db; init_db()"
3. Run UI:
   streamlit run streamlit_app.py

CLI is available under src/cli.py for scripting and automated tests.
