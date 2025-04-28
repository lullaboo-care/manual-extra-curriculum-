#!/usr/bin/env python3
"""
Setup script for the FileMaker to Firebase Data Transfer Tool.
This script helps with setting up the directory structure and dependencies.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def print_header(message):
    """Print a formatted header message."""
    print("\n" + "=" * 60)
    print(f" {message}")
    print("=" * 60)

def check_python_version():
    """Check that Python version is 3.7+."""
    print_header("Checking Python version")
    
    if sys.version_info < (3, 7):
        print("❌ Python 3.7 or higher is required!")
        print(f"Current version: {sys.version}")
        sys.exit(1)
    
    print(f"✅ Python version {sys.version.split()[0]} detected.")

def install_dependencies():
    """Install required Python packages."""
    print_header("Installing dependencies")
    
    dependencies = ["flask", "firebase-admin", "requests"]
    
    for package in dependencies:
        print(f"Installing {package}...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"✅ {package} installed successfully.")
        except subprocess.CalledProcessError:
            print(f"❌ Failed to install {package}.")
            sys.exit(1)

def create_directory_structure():
    """Create the necessary directory structure."""
    print_header("Creating directory structure")
    
    # Define directories to create
    directories = ["static"]
    
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            print(f"✅ Created directory: {directory}")
        except Exception as e:
            print(f"❌ Failed to create directory {directory}: {e}")
            sys.exit(1)

def copy_files():
    """Copy the necessary files to their locations."""
    print_header("Setting up application files")
    
    # Check if frontend and backend files exist
    frontend_files = ["frontend-app.html", "index.html"]
    frontend_source = None
    
    for file in frontend_files:
        if os.path.exists(file):
            frontend_source = file
            break
    
    if not frontend_source:
        print("❌ Frontend HTML file not found. Expected 'frontend-app.html' or 'index.html'.")
        sys.exit(1)
    
    # Look for backend file
    backend_files = ["backend-flask.py", "app.py"]
    backend_source = None
    
    for file in backend_files:
        if os.path.exists(file):
            backend_source = file
            break
    
    if not backend_source:
        print("❌ Backend Flask file not found. Expected 'backend-flask.py' or 'app.py'.")
        sys.exit(1)
    
    # Copy frontend file to static/index.html
    try:
        shutil.copy2(frontend_source, "static/index.html")
        print(f"✅ Copied {frontend_source} to static/index.html")
    except Exception as e:
        print(f"❌ Failed to copy frontend file: {e}")
        sys.exit(1)
    
    # Copy backend file to app.py if it's not already there
    if backend_source != "app.py":
        try:
            shutil.copy2(backend_source, "app.py")
            print(f"✅ Copied {backend_source} to app.py")
        except Exception as e:
            print(f"❌ Failed to copy backend file: {e}")
            sys.exit(1)
    else:
        print("✅ Backend file is already named app.py")

def check_file_permissions():
    """Make sure app.py is executable."""
    print_header("Setting file permissions")
    
    try:
        app_py = Path("app.py")
        app_py.chmod(app_py.stat().st_mode | 0o111)  # Add executable bit
        print("✅ Made app.py executable")
    except Exception as e:
        print(f"❌ Failed to set file permissions: {e}")
        print("You may need to manually make app.py executable.")

def print_instructions():
    """Print instructions for running the application."""
    print_header("Setup Complete! 🎉")
    print("""
To run the application:

1. Start the Flask server:
   $ python app.py

2. Open your web browser and go to:
   http://localhost:5000

3. Configure your FileMaker and Firebase credentials in the Configuration tab.

4. Start transferring data from the Data Transfer tab.

For more information, please refer to the README.md file.
""")

def main():
    """Main function to run all setup steps."""
    print_header("FileMaker to Firebase Transfer Tool Setup")
    
    check_python_version()
    install_dependencies()
    create_directory_structure()
    copy_files()
    check_file_permissions()
    print_instructions()

if __name__ == "__main__":
    main()