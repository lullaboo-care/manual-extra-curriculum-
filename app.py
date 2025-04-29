from flask import Flask, request, jsonify, send_from_directory, render_template
from flask_cors import CORS  # Recommended for handling cross-origin requests
import base64
import json
import re
import requests
import os
import firebase_admin
from firebase_admin import credentials
from firebase_admin import db
import threading
import time
import logging
from flask import Flask, send_from_directory
from firebase_config import SERVICE_ACCOUNT_CONFIG


# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

print("Starting Lullaboo Data Transfer Tool...")
print("Server will be available at http://localhost:6100")

app = Flask(__name__, static_folder='public', static_url_path='')

# Global variables
transfer_in_progress = False
transfer_progress = {}
campus_progress = {}
error_log = []

# Hardcoded campus list
campus_list = [
    'avenue', 'bedford', 'bradford', 'beaches',
    'homestead', 'wanless', 'cambridge', 'meadowvale',
    'heartland', 'elgin', 'maple', 'college',
    'churchill', 'aurora', 'queen', 'ninth', 'miltoneast'
]

# Hardcoded campusID mapping
campus_ids = {
    'heartland': 5,
    'churchill': 16,
    'maple': 1,
    'elgin': 3,
    'queen': 4,
    'ninth': 2,
    'beaches': 7,
    'cambridge': 8,
    'bradford': 9,
    'college': 10,
    'meadowvale': 11,
    'aurora': 12,
    'wanless': 13,
    'avenue': 14,
    'bedford': 15,
    'homestead': 17,
    'miltoneast': 18
}

# Initialize Firebase app variable
firebase_app = None

# ------------------------------------------------
# Common Helper Functions
# ------------------------------------------------

def initialize_firebase(database_url):
    """Initialize Firebase with the service account credentials"""
    global firebase_app
    
    # If firebase_app already exists, delete it
    if firebase_app:
        try:
            firebase_admin.delete_app(firebase_app)
        except:
            pass
    
    try:
        # Create a temporary file for the service account key
        temp_file_path = 'temp_service_account.json'
        with open(temp_file_path, 'w') as f:
            json.dump(SERVICE_ACCOUNT_CONFIG, f)
        
        cred = credentials.Certificate(temp_file_path)
        firebase_app = firebase_admin.initialize_app(cred, {
            'databaseURL': database_url
        })
        
        # Test connection by accessing a reference
        test_ref = db.reference('/')
        test_ref.get()  # This will throw an exception if there's a connection issue
        
        # Clean up temp file
        os.remove(temp_file_path)
        return True
    except Exception as e:
        logger.error(f"Firebase initialization error: {str(e)}")
        
        # Clean up temp file
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
        return False

def sanitize_key(key_string: str) -> str:
    """
    1) Strip leading/trailing whitespace.
    2) Convert any sequence of whitespace to a single space.
    3) Replace forbidden Firebase chars ('.', '#', '$', '[', ']', '/') with underscores.
    """
    if not key_string:
        return "unknown"
        
    # Strip leading/trailing
    key_string = key_string.strip()
    # Convert multiple whitespace chars to single space
    key_string = re.sub(r"\s+", " ", key_string)
    # Replace forbidden Firebase chars
    key_string = re.sub(r"[.#$/\[\]]", "_", key_string)

    return key_string

# ------------------------------------------------
# Child Schedule Functions
# ------------------------------------------------

def build_childschedule_endpoints(campus_name):
    base_url = f"https://{campus_name}.lullaboo.com/fmi/data/v1/databases/iCare"
    session_endpoint = f"{base_url}/sessions"
    find_endpoint = f"{base_url}/layouts/childSchedule/_find"
    return session_endpoint, find_endpoint

def get_filemaker_token(session_endpoint, username, password):
    auth_str = f"{username}:{password}"
    encoded_auth = base64.b64encode(auth_str.encode()).decode()

    headers = {
        "Authorization": f"Basic {encoded_auth}",
        "Content-Type": "application/json"
    }
    response = requests.post(session_endpoint, headers=headers)
    response.raise_for_status()

    json_data = response.json()
    token = json_data["response"]["token"]
    return token

def query_child_schedule(find_endpoint, token, offset=1, limit=100):
    """Query records where 'tillDate = 12/31/2999'."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "query": [
            {"tillDate": "=12/31/2999"}
        ],
        "limit": limit,
        "offset": offset
    }

    response = requests.post(find_endpoint, headers=headers, json=payload)
    response.raise_for_status()
    return response.json()

def get_all_child_schedules(find_endpoint, token, limit=100):
    """
    Retrieve ALL childSchedule records by looping with offset/limit
    until no more data is returned.
    """
    all_records = []
    offset = 1  # If you only see 100, try offset=0

    while True:
        response_json = query_child_schedule(find_endpoint, token, offset=offset, limit=limit)
        data_chunk = response_json["response"].get("data", [])

        if not data_chunk:
            break

        all_records.extend(data_chunk)

        if len(data_chunk) < limit:
            break

        offset += limit

    return all_records

def insert_childschedule_records_into_rtdb(records, campus_name):
    """
    Insert records under:
        /childSchedulesv1/<campusName>/<childName>
    """
    campus_name_safe = sanitize_key(campus_name)
    campus_id = campus_ids.get(campus_name.lower(), None)

    # Use "childSchedulesv1" or any other node you'd like
    campus_ref = db.reference("childSchedulesv1").child(campus_name_safe)

    total_inserted = 0

    for idx, record in enumerate(records, start=1):
        field_data = record.get("fieldData", {})

        # Convert childID to string to avoid scientific notation
        raw_child_id = field_data.get("childID")
        child_id_str = str(raw_child_id) if raw_child_id is not None else ""

        effective_date = field_data.get("effectiveDate")
        till_date = field_data.get("tillDate")
        child_name = field_data.get("childName", "Unknown")

        # Debug info
        logger.debug(f"Inserting record #{idx} for childName='{child_name}', childID='{child_id_str}'")

        # Sanitize child name
        child_name_safe = sanitize_key(child_name)

        doc_data = {
            "childID": child_id_str,  # always a string now
            "childName": child_name,
            "effectiveDate": effective_date,
            "tillDate": till_date,
            "campus": campus_name,
            "campusID": campus_id
        }

        try:
            child_name_ref = campus_ref.child(child_name_safe)
            child_name_ref.set(doc_data)
            total_inserted += 1
        except Exception as e:
            logger.error(f"Failed to insert record #{idx} (childName='{child_name}'): {e}")
            error_log.append(f"Failed to insert record #{idx} (childName='{child_name}'): {e}")

    logger.info(f"Inserted/Overwritten {total_inserted} out of {len(records)} records for campus '{campus_name}'.")
    return total_inserted

def process_childschedule_campus(campus, filemaker_username, filemaker_password):
    """Process child schedule data for a single campus and update progress"""
    global campus_progress, transfer_progress
    
    # Update progress status
    campus_progress[campus] = {
        "status": "processing",
        "message": f"Starting child schedule process for {campus}...",
        "records_retrieved": 0,
        "records_inserted": 0
    }
    
    try:
        session_endpoint, find_endpoint = build_childschedule_endpoints(campus)
        
        # Get FileMaker token
        token = get_filemaker_token(session_endpoint, filemaker_username, filemaker_password)
        campus_progress[campus]["message"] = f"Acquired token for {campus}, retrieving child schedule records..."
        
        # Get all child schedules
        records = get_all_child_schedules(find_endpoint, token, limit=100)
        total_recs = len(records)
        campus_progress[campus]["records_retrieved"] = total_recs
        campus_progress[campus]["message"] = f"Retrieved {total_recs} child schedule records for {campus}, inserting into Firebase..."
        
        # Process records if any were found
        if records:
            inserted = insert_childschedule_records_into_rtdb(records, campus)
            campus_progress[campus]["records_inserted"] = inserted
            campus_progress[campus]["status"] = "completed"
            campus_progress[campus]["message"] = f"Completed processing {campus}. Inserted {inserted} out of {total_recs} child schedule records."
        else:
            campus_progress[campus]["status"] = "completed"
            campus_progress[campus]["message"] = f"No child schedule records found for {campus}."
        
        # Update overall progress
        completed_campuses = sum(1 for c in campus_progress if campus_progress[c]["status"] in ["completed", "error"])
        total_campuses = len(transfer_progress["selected_campuses"])
        transfer_progress["progress_percent"] = int((completed_campuses / total_campuses) * 100)
        
    except requests.exceptions.HTTPError as http_err:
        error_msg = f"HTTP error for '{campus}': {http_err}"
        logger.error(error_msg)
        error_log.append(error_msg)
        campus_progress[campus]["status"] = "error"
        campus_progress[campus]["message"] = error_msg
    except Exception as e:
        error_msg = f"Error processing '{campus}': {e}"
        logger.error(error_msg)
        error_log.append(error_msg)
        campus_progress[campus]["status"] = "error"
        campus_progress[campus]["message"] = error_msg
    
    # Update overall progress regardless of success/failure
    completed_campuses = sum(1 for c in campus_progress if campus_progress[c]["status"] in ["completed", "error"])
    total_campuses = len(transfer_progress["selected_campuses"])
    transfer_progress["progress_percent"] = int((completed_campuses / total_campuses) * 100)
    
    # Check if all campuses are done
    if completed_campuses == total_campuses:
        transfer_progress["status"] = "completed"
        transfer_progress["end_time"] = time.time()
        transfer_progress["duration"] = transfer_progress["end_time"] - transfer_progress["start_time"]
        transfer_progress["message"] = f"Transfer completed in {transfer_progress['duration']:.2f} seconds"
        global transfer_in_progress
        transfer_in_progress = False

# ------------------------------------------------
# Authorization Functions
# ------------------------------------------------

def build_authorization_endpoints(campus_name):
    base_url = f"https://{campus_name}.lullaboo.com"
    session_endpoint = f"{base_url}/fmi/data/v1/databases/iCareMobileAccess/sessions"
    find_endpoint = f"{base_url}/fmi/data/v1/databases/iCareMobileAccess/layouts/authorizationLineItemAnswerMobile/_find"
    return session_endpoint, find_endpoint

def query_authorization_data(find_endpoint, token, template_id, offset=1, limit=100):
    """Query authorization records for the given template ID."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "query": [
            {"authorizationTemplateID": template_id}
        ],
        "limit": limit,
        "offset": offset
    }

    response = requests.post(find_endpoint, headers=headers, json=payload)
    response.raise_for_status()
    return response.json()

def get_all_authorization_data(find_endpoint, token, template_id, limit=100):
    """
    Retrieve ALL authorization records for the template by looping with offset/limit
    until no more data is returned.
    """
    all_records = []
    offset = 1

    while True:
        response_json = query_authorization_data(find_endpoint, token, template_id, offset=offset, limit=limit)
        data_chunk = response_json["response"].get("data", [])

        if not data_chunk:
            break

        all_records.extend(data_chunk)

        if len(data_chunk) < limit:
            break

        offset += limit

    return all_records

def process_authorization_data(records, campus):
    """Process and transform authorization data for Firebase."""
    processed_data = []
    
    fields_to_get = [
        "authorizationLineItemAnswerID",
        "authorizationQuestion01",
        "child::childID",
        "authorizationAnswer01Text"
    ]
    
    for record in records:
        field_data = record.get("fieldData", {})
        result = {
            field: str(field_data.get(field)) if field == "child::childID" else field_data.get(field)
            for field in fields_to_get if field in field_data
        }
        result["campusName"] = campus
        result["campusID"] = campus_ids.get(campus.lower())
        processed_data.append(result)
    
    return processed_data

def insert_authorization_records_into_rtdb(records, campus_name):
    """Insert authorization records into Firebase under /authorizationAnswers/campus."""
    ref_path = f"/authorizationAnswers/{campus_name}"
    ref = db.reference(ref_path)
    
    total_inserted = 0
    
    for record in records:
        key = record.get("authorizationLineItemAnswerID")
        if key:
            try:
                ref.child(key).set(record)
                total_inserted += 1
            except Exception as e:
                logger.error(f"Failed to insert authorization record: {e}")
                error_log.append(f"Failed to insert authorization record: {e}")
    
    logger.info(f"Inserted {total_inserted} out of {len(records)} authorization records for campus '{campus_name}'.")
    return total_inserted

def process_authorization_campus(campus, filemaker_username, filemaker_password, template_id):
    """Process authorization data for a single campus and update progress"""
    global campus_progress, transfer_progress
    
    # Update progress status
    campus_progress[campus] = {
        "status": "processing",
        "message": f"Starting authorization process for {campus}...",
        "records_retrieved": 0,
        "records_inserted": 0
    }
    
    try:
        session_endpoint, find_endpoint = build_authorization_endpoints(campus)
        
        # Get FileMaker token
        token = get_filemaker_token(session_endpoint, filemaker_username, filemaker_password)
        campus_progress[campus]["message"] = f"Acquired token for {campus}, retrieving authorization records..."
        
        # Get all authorization records
        records = get_all_authorization_data(find_endpoint, token, template_id, limit=100)
        total_recs = len(records)
        campus_progress[campus]["records_retrieved"] = total_recs
        campus_progress[campus]["message"] = f"Retrieved {total_recs} authorization records for {campus}, processing data..."
        
        # Process records if any were found
        if records:
            processed_records = process_authorization_data(records, campus)
            inserted = insert_authorization_records_into_rtdb(processed_records, campus)
            campus_progress[campus]["records_inserted"] = inserted
            campus_progress[campus]["status"] = "completed"
            campus_progress[campus]["message"] = f"Completed processing {campus}. Inserted {inserted} out of {total_recs} authorization records."
        else:
            campus_progress[campus]["status"] = "completed"
            campus_progress[campus]["message"] = f"No authorization records found for {campus}."
        
        # Update overall progress
        completed_campuses = sum(1 for c in campus_progress if campus_progress[c]["status"] in ["completed", "error"])
        total_campuses = len(transfer_progress["selected_campuses"])
        transfer_progress["progress_percent"] = int((completed_campuses / total_campuses) * 100)
        
    except requests.exceptions.HTTPError as http_err:
        error_msg = f"HTTP error for '{campus}': {http_err}"
        logger.error(error_msg)
        error_log.append(error_msg)
        campus_progress[campus]["status"] = "error"
        campus_progress[campus]["message"] = error_msg
    except Exception as e:
        error_msg = f"Error processing '{campus}': {e}"
        logger.error(error_msg)
        error_log.append(error_msg)
        campus_progress[campus]["status"] = "error"
        campus_progress[campus]["message"] = error_msg
    
    # Update overall progress regardless of success/failure
    completed_campuses = sum(1 for c in campus_progress if campus_progress[c]["status"] in ["completed", "error"])
    total_campuses = len(transfer_progress["selected_campuses"])
    transfer_progress["progress_percent"] = int((completed_campuses / total_campuses) * 100)
    
    # Check if all campuses are done
    if completed_campuses == total_campuses:
        transfer_progress["status"] = "completed"
        transfer_progress["end_time"] = time.time()
        transfer_progress["duration"] = transfer_progress["end_time"] - transfer_progress["start_time"]
        transfer_progress["message"] = f"Transfer completed in {transfer_progress['duration']:.2f} seconds"
        global transfer_in_progress
        transfer_in_progress = False

# ------------------------------------------------
# Main Transfer Process
# ------------------------------------------------

def run_data_transfer(selected_campuses, filemaker_username, filemaker_password, transfer_type="childSchedule", authorization_template_id=None):
    """Run the data transfer process for selected campuses"""
    global transfer_in_progress, transfer_progress, campus_progress, error_log
    
    if transfer_in_progress:
        return {"success": False, "message": "Transfer already in progress"}
    
    # Reset progress tracking
    transfer_in_progress = True
    transfer_progress = {
        "status": "in_progress",
        "selected_campuses": selected_campuses,
        "total_campuses": len(selected_campuses),
        "completed_campuses": 0,
        "progress_percent": 0,
        "start_time": time.time(),
        "end_time": None,
        "duration": None,
        "transfer_type": transfer_type,
        "message": f"Starting {transfer_type} transfer process..."
    }
    campus_progress = {campus: {"status": "pending"} for campus in selected_campuses}
    error_log = []
    
    # Process each campus in its own thread
    threads = []
    for campus in selected_campuses:
        if transfer_type == "childSchedule":
            thread = threading.Thread(
                target=process_childschedule_campus, 
                args=(campus, filemaker_username, filemaker_password)
            )
        elif transfer_type == "authorization":
            thread = threading.Thread(
                target=process_authorization_campus, 
                args=(campus, filemaker_username, filemaker_password, authorization_template_id)
            )
        elif transfer_type == "childSync":
            thread = threading.Thread(
                target=process_childsync_campus, 
                args=(campus, filemaker_username, filemaker_password)
            )
        else:
            return {"success": False, "message": f"Unknown transfer type: {transfer_type}"}
            
        thread.daemon = True
        thread.start()
        threads.append(thread)
        # Small delay to avoid overwhelming the server with requests
        time.sleep(0.5)
    
    return {"success": True, "message": f"{transfer_type} transfer process started"}
# ------------------------------------------------
# Child Sync Functions
# ------------------------------------------------

def build_childsync_endpoints(campus_name):
    """Build FileMaker API endpoints for child sync"""
    base_url = f"https://{campus_name}.lullaboo.com/fmi/data/v1/databases/iCare"
    session_endpoint = f"{base_url}/sessions"
    find_endpoint = f"{base_url}/layouts/child/_find"
    return session_endpoint, find_endpoint

def query_child_data(find_endpoint, token, offset=1, limit=100):
    """Query child records with campusID > 0"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "query": [
            {"campusID": ">0"}
        ],
        "limit": limit,
        "offset": offset
    }

    response = requests.post(find_endpoint, headers=headers, json=payload)
    response.raise_for_status()
    return response.json()

def get_all_child_data(find_endpoint, token, limit=100):
    """Retrieve ALL child records by looping with offset/limit"""
    all_records = []
    offset = 1

    while True:
        response_json = query_child_data(find_endpoint, token, offset=offset, limit=limit)
        data_chunk = response_json["response"].get("data", [])

        if not data_chunk:
            break

        all_records.extend(data_chunk)

        if len(data_chunk) < limit:
            break

        offset += limit

    return all_records

def insert_childsync_records_into_rtdb(records, campus_name):
    """Insert child records into Firebase under /campuses/campus_name/"""
    ref = db.reference(f"campuses/{campus_name}/")
    
    # Get existing data to identify records to delete
    existing_data = ref.get() or {}
    
    # Process new records
    desired_fields = [
        "stillRegistered",
        "childID",
        "primaryParentID",
        "campusID",
        "childNameFirstLast",
        "subsidyChildID"
    ]
    
    filemaker_ids = set()
    new_data = {}

    for record in records:
        field_data = record.get('fieldData', {})
        child_id = str(field_data.get('childID'))
        gate_name = field_data.get('childNameFirstLast', 'unknown')
        unique_key = gate_name.replace(' ', '_') if gate_name else f"child_{child_id}"
        
        filemaker_ids.add(unique_key)

        filtered_data = {
            key: str(field_data.get(key)) if key == "childID" and field_data.get(key) is not None else field_data.get(key)
            for key in desired_fields if key in field_data
        }

        new_data[unique_key] = filtered_data
    
    # Determine which keys should be deleted
    existing_keys = set(existing_data.keys())
    keys_to_remove = existing_keys - filemaker_ids
    
    total_deleted = 0
    for key in keys_to_remove:
        ref.child(key).delete()
        total_deleted += 1
    
    # Update with new records
    ref.update(new_data)
    
    return len(new_data), total_deleted

def process_childsync_campus(campus, filemaker_username, filemaker_password):
    """Process child sync data for a single campus and update progress"""
    global campus_progress, transfer_progress
    
    # Update progress status
    campus_progress[campus] = {
        "status": "processing",
        "message": f"Starting child sync process for {campus}...",
        "records_retrieved": 0,
        "records_inserted": 0,
        "records_deleted": 0
    }
    
    try:
        session_endpoint, find_endpoint = build_childsync_endpoints(campus)
        
        # Get FileMaker token
        token = get_filemaker_token(session_endpoint, filemaker_username, filemaker_password)
        campus_progress[campus]["message"] = f"Acquired token for {campus}, retrieving child records..."
        
        # Get all child data
        records = get_all_child_data(find_endpoint, token, limit=100)
        total_recs = len(records)
        campus_progress[campus]["records_retrieved"] = total_recs
        campus_progress[campus]["message"] = f"Retrieved {total_recs} child records for {campus}, processing data..."
        
        # Process records if any were found
        if records:
            inserted, deleted = insert_childsync_records_into_rtdb(records, campus)
            campus_progress[campus]["records_inserted"] = inserted
            campus_progress[campus]["records_deleted"] = deleted
            campus_progress[campus]["status"] = "completed"
            campus_progress[campus]["message"] = f"Completed processing {campus}. Inserted {inserted} records, deleted {deleted} outdated records."
        else:
            campus_progress[campus]["status"] = "completed"
            campus_progress[campus]["message"] = f"No child records found for {campus}."
        
        # Update overall progress
        completed_campuses = sum(1 for c in campus_progress if campus_progress[c]["status"] in ["completed", "error"])
        total_campuses = len(transfer_progress["selected_campuses"])
        transfer_progress["progress_percent"] = int((completed_campuses / total_campuses) * 100)
        
    except requests.exceptions.HTTPError as http_err:
        error_msg = f"HTTP error for '{campus}': {http_err}"
        logger.error(error_msg)
        error_log.append(error_msg)
        campus_progress[campus]["status"] = "error"
        campus_progress[campus]["message"] = error_msg
    except Exception as e:
        error_msg = f"Error processing '{campus}': {e}"
        logger.error(error_msg)
        error_log.append(error_msg)
        campus_progress[campus]["status"] = "error"
        campus_progress[campus]["message"] = error_msg
    
    # Update overall progress regardless of success/failure
    completed_campuses = sum(1 for c in campus_progress if campus_progress[c]["status"] in ["completed", "error"])
    total_campuses = len(transfer_progress["selected_campuses"])
    transfer_progress["progress_percent"] = int((completed_campuses / total_campuses) * 100)
    
    # Check if all campuses are done
    if completed_campuses == total_campuses:
        transfer_progress["status"] = "completed"
        transfer_progress["end_time"] = time.time()
        transfer_progress["duration"] = transfer_progress["end_time"] - transfer_progress["start_time"]
        transfer_progress["message"] = f"Transfer completed in {transfer_progress['duration']:.2f} seconds"
        global transfer_in_progress
        transfer_in_progress = False

# ------------------------------------------------
# Flask Routes
# ------------------------------------------------

@app.route('/')
def index():
    """Serve the main HTML page"""
    return send_from_directory('public', 'index.html')

# Add CORS support
# Enable CORS
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Optional: Add error handling middleware
@app.errorhandler(404)
def page_not_found(e):
    return jsonify(error=str(e)), 404

@app.errorhandler(500)
def internal_server_error(e):
    return jsonify(error=str(e)), 500

@app.route('/api/start_transfer', methods=['POST'])
def start_transfer():
    global transfer_in_progress, transfer_progress, campus_progress, error_log
    
    if transfer_in_progress:
        return jsonify({
            'success': False,
            'message': 'A transfer is already in progress'
        })
    
    data = request.get_json()
    
    # Extract data from request
    selected_campuses = data.get('campuses', [])
    filemaker_username = data.get('filemaker_username')
    filemaker_password = data.get('filemaker_password')
    firebase_url = data.get('firebase_url')
    transfer_type = data.get('transfer_type', 'childSchedule')
    authorization_template_id = data.get('authorization_template_id')
    
    # Validate required fields
    if not all([selected_campuses, filemaker_username, filemaker_password, firebase_url]):
        return jsonify({
            'success': False,
            'message': 'Missing required fields'
        })
    
    # Initialize Firebase
    if not initialize_firebase(firebase_url):
        return jsonify({
            'success': False,
            'message': 'Failed to initialize Firebase connection'
        })
    
    # Reset progress tracking
    transfer_progress = {
        'progress_percent': 0,
        'message': 'Starting transfer...'
    }
    campus_progress = {}
    error_log = []
    
    # Start transfer in a new thread
    transfer_thread = threading.Thread(
        target=run_data_transfer,
        args=(selected_campuses, filemaker_username, filemaker_password, transfer_type, authorization_template_id)
    )
    transfer_thread.start()
    
    return jsonify({
        'success': True,
        'message': 'Transfer started successfully'
    })

@app.route('/api/stop_transfer', methods=['POST'])
def stop_transfer():
    """Stop the data transfer process"""
    global transfer_in_progress, transfer_progress
    
    if not transfer_in_progress:
        return jsonify({
            "success": False,
            "message": "No transfer in progress"
        })
    
    transfer_in_progress = False
    transfer_progress["status"] = "stopped"
    transfer_progress["message"] = "Transfer stopped by user"
    
    return jsonify({
        "success": True,
        "message": "Transfer process stopped"
    })

@app.route('/api/transfer_status', methods=['GET'])
def transfer_status():
    """Get the current transfer status"""
    return jsonify({
        "in_progress": transfer_in_progress,
        "progress": transfer_progress,
        "campus_status": campus_progress,
        "errors": error_log
    })

@app.route('/api/test_connection', methods=['POST'])
def test_connection():
    data = request.get_json()
    
    # Extract credentials
    filemaker_username = data.get('filemaker_username')
    filemaker_password = data.get('filemaker_password')
    firebase_url = data.get('firebase_url')
    test_campus = data.get('test_campus', 'heartland')
    transfer_type = data.get('transfer_type', 'childSchedule')
    
    result = {
        'filemaker': {'success': False, 'message': ''},
        'firebase': {'success': False, 'message': ''}
    }
    
    # Test FileMaker connection
    try:
        if transfer_type == 'childSchedule':
            session_endpoint, _ = build_childschedule_endpoints(test_campus)
        elif transfer_type == 'authorization':
            session_endpoint, _ = build_authorization_endpoints(test_campus)
        else:  # childSync
            session_endpoint, _ = build_childsync_endpoints(test_campus)
            
        get_filemaker_token(session_endpoint, filemaker_username, filemaker_password)
        result['filemaker'] = {
            'success': True,
            'message': 'Successfully connected to FileMaker'
        }
    except Exception as e:
        result['filemaker'] = {
            'success': False,
            'message': str(e)
        }
    
    # Test Firebase connection
    try:
        if initialize_firebase(firebase_url):
            result['firebase'] = {
                'success': True,
                'message': 'Successfully connected to Firebase'
            }
        else:
            result['firebase'] = {
                'success': False,
                'message': 'Failed to initialize Firebase connection'
            }
    except Exception as e:
        result['firebase'] = {
            'success': False,
            'message': str(e)
        }
    
    return jsonify(result)

@app.route('/api/campus_list', methods=['GET'])
def get_campus_list():
    """Get list of available campuses"""
    campus_data = {}
    for campus in campus_list:
        campus_id = campus_ids.get(campus.lower(), None)
        # Generate a readable name by capitalizing and handling special cases
        readable_name = campus.capitalize()
        if campus == "miltoneast":
            readable_name = "Milton East"
        
        campus_data[campus] = {
            "id": campus_id,
            "name": readable_name
        }
    
    return jsonify({
        "success": True,
        "campuses": campus_data
    })

if __name__ == '__main__':
    app.run(debug=True, port=6100)  # Change port to 6000 to avoid conflict with other services