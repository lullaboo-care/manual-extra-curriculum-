# Lullaboo Data Transfer Tool

A Flask-based web application for transferring and synchronizing data between FileMaker databases and Firebase Realtime Database.

## Features

- Child Schedule Transfer: Sync child schedules from FileMaker to Firebase
- Authorization Data Transfer: Transfer authorization data with template support
- Child Sync: Synchronize child records between systems
- Real-time Progress Tracking: Monitor transfer progress for each campus
- Multi-campus Support: Process multiple campuses simultaneously
- Error Logging: Comprehensive error tracking and reporting

## Prerequisites

- Python 3.7+
- Flask
- Firebase Admin SDK
- FileMaker Data API access
- Modern web browser

## Installation

1. Clone the repository:
```bash
git clone [repository-url]
cd manual-extra-curriculum-
```

2. Install required Python packages:
```bash
pip install -r requirements.txt
```

3. Configure Firebase:
   - Create a Firebase project
   - Set up Realtime Database
   - Download service account credentials
   - Update Firebase configuration in the application

## Configuration

1. Firebase Configuration:
   - Place your Firebase service account credentials in the application
   - Configure the Firebase Realtime Database URL

2. FileMaker Configuration:
   - Ensure FileMaker Data API is enabled
   - Have valid FileMaker credentials ready

## Usage

1. Start the server:
```bash
python app.py
```

2. Access the web interface:
   - Open your browser and navigate to `http://localhost:6100`
   - The application will be available at this address

3. Using the Interface:
   - Enter FileMaker credentials
   - Enter Firebase Database URL
   - Select campuses to process
   - Choose transfer type (Child Schedule/Authorization/Child Sync)
   - Start the transfer process
   - Monitor progress in real-time

## API Endpoints

- `/api/start_transfer` - Start data transfer process
- `/api/stop_transfer` - Stop ongoing transfer
- `/api/transfer_status` - Get current transfer status
- `/api/test_connection` - Test FileMaker and Firebase connections
- `/api/campus_list` - Get list of available campuses

## Error Handling

The application includes comprehensive error handling:
- Connection errors
- Authentication failures
- Data processing errors
- Transfer interruptions

## Security Considerations

- Credentials are not stored
- CORS enabled for API endpoints
- Secure handling of service account credentials
- Input validation and sanitization

## Troubleshooting

Common issues and solutions:
1. Connection Failures:
   - Verify FileMaker credentials
   - Check Firebase configuration
   - Ensure network connectivity

2. Transfer Issues:
   - Check error logs
   - Verify data format
   - Ensure sufficient permissions

## Support

For support or questions, please contact the development team.

## License

[License Information]