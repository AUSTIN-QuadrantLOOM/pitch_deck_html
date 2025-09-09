"""
Quadrant Loom AI Surveillance System
Community-based security solution with machine learning threat detection

This system provides:
- Real-time video analysis for threat detection
- Community alert system
- Privacy-preserving recognition
- Integration with nyumba kumi structure
"""

import cv2
import numpy as np
import tensorflow as tf
from tensorflow import keras
from datetime import datetime, timedelta
import sqlite3
import json
import hashlib
import threading
import time
from collections import deque
import logging
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
import smtplib
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ThreatAlert:
    """Data class for threat alerts"""
    alert_id: str
    timestamp: datetime
    threat_type: str
    confidence: float
    location: str
    description: str
    camera_id: str
    community_id: str
    severity: str  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'

class DatabaseManager:
    """Manages SQLite database operations for the surveillance system"""
    
    def __init__(self, db_path: str = "quadrant_loom.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Communities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS communities (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                location TEXT,
                contact_person TEXT,
                phone_number TEXT,
                huduma_number TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Cameras table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cameras (
                id TEXT PRIMARY KEY,
                community_id TEXT,
                location TEXT,
                ip_address TEXT,
                status TEXT DEFAULT 'ACTIVE',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (community_id) REFERENCES communities (id)
            )
        ''')
        
        # Alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                community_id TEXT,
                camera_id TEXT,
                threat_type TEXT,
                confidence REAL,
                severity TEXT,
                description TEXT,
                timestamp TIMESTAMP,
                status TEXT DEFAULT 'ACTIVE',
                FOREIGN KEY (community_id) REFERENCES communities (id),
                FOREIGN KEY (camera_id) REFERENCES cameras (id)
            )
        ''')
        
        # Users table (privacy-preserving)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                community_id TEXT,
                huduma_hash TEXT,  -- Hashed huduma number for privacy
                phone_number TEXT,
                notification_preferences TEXT,  -- JSON string
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (community_id) REFERENCES communities (id)
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")

class ThreatDetectionModel:
    """AI model for threat detection in surveillance footage"""
    
    def __init__(self):
        self.model = None
        self.threat_classes = [
            'normal', 'intrusion', 'fighting', 'fire', 'suspicious_person',
            'vandalism', 'crowd_gathering', 'vehicle_speeding', 'weapon_detection'
        ]
        self.confidence_threshold = 0.7
        self.setup_model()
    
    def setup_model(self):
        """Setup the neural network model for threat detection"""
        # Create a simplified CNN model for demonstration
        # In production, you would use a pre-trained model like MobileNet or EfficientNet
        
        model = keras.Sequential([
            keras.layers.Conv2D(32, (3, 3), activation='relu', input_shape=(224, 224, 3)),
            keras.layers.MaxPooling2D(2, 2),
            keras.layers.Conv2D(64, (3, 3), activation='relu'),
            keras.layers.MaxPooling2D(2, 2),
            keras.layers.Conv2D(128, (3, 3), activation='relu'),
            keras.layers.MaxPooling2D(2, 2),
            keras.layers.Flatten(),
            keras.layers.Dropout(0.5),
            keras.layers.Dense(512, activation='relu'),
            keras.layers.Dense(len(self.threat_classes), activation='softmax')
        ])
        
        model.compile(
            optimizer='adam',
            loss='categorical_crossentropy',
            metrics=['accuracy']
        )
        
        self.model = model
        logger.info("Threat detection model initialized")
    
    def preprocess_frame(self, frame: np.ndarray) -> np.ndarray:
        """Preprocess video frame for model input"""
        # Resize frame to model input size
        frame_resized = cv2.resize(frame, (224, 224))
        # Normalize pixel values
        frame_normalized = frame_resized.astype('float32') / 255.0
        # Add batch dimension
        frame_batch = np.expand_dims(frame_normalized, axis=0)
        return frame_batch
    
    def detect_threats(self, frame: np.ndarray) -> Tuple[str, float]:
        """Detect threats in a video frame"""
        if self.model is None:
            return 'normal', 0.0
        
        try:
            # Preprocess frame
            processed_frame = self.preprocess_frame(frame)
            
            # Make prediction
            predictions = self.model.predict(processed_frame, verbose=0)
            predicted_class_idx = np.argmax(predictions[0])
            confidence = float(predictions[0][predicted_class_idx])
            threat_type = self.threat_classes[predicted_class_idx]
            
            return threat_type, confidence
            
        except Exception as e:
            logger.error(f"Error in threat detection: {e}")
            return 'normal', 0.0
    
    def train_model(self, training_data_path: str):
        """Train the model with labeled data"""
        # This is a placeholder for actual training implementation
        # In production, you would load labeled surveillance data
        logger.info(f"Training model with data from {training_data_path}")
        # Implementation would include data loading, augmentation, and training loop

class CommunityNotificationSystem:
    """Handles community notifications and alerts"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.notification_queue = deque()
        self.sms_service = None  # Would integrate with SMS gateway
        self.email_service = None  # Would integrate with email service
        
    def hash_huduma_number(self, huduma_number: str) -> str:
        """Hash huduma number for privacy protection"""
        return hashlib.sha256(huduma_number.encode()).hexdigest()
    
    def register_community_member(self, community_id: str, huduma_number: str, 
                                 phone_number: str, notification_prefs: Dict):
        """Register a community member with privacy protection"""
        conn = sqlite3.connect(self.db_manager.db_path)
        cursor = conn.cursor()
        
        user_id = hashlib.md5(f"{community_id}{huduma_number}".encode()).hexdigest()
        huduma_hash = self.hash_huduma_number(huduma_number)
        
        cursor.execute('''
            INSERT OR REPLACE INTO users 
            (id, community_id, huduma_hash, phone_number, notification_preferences)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, community_id, huduma_hash, phone_number, 
              json.dumps(notification_prefs)))
        
        conn.commit()
        conn.close()
        logger.info(f"Community member registered for community {community_id}")
    
    def send_community_alert(self, alert: ThreatAlert):
        """Send alert to community members"""
        conn = sqlite3.connect(self.db_manager.db_path)
        cursor = conn.cursor()
        
        # Get community members
        cursor.execute('''
            SELECT phone_number, notification_preferences 
            FROM users 
            WHERE community_id = ?
        ''', (alert.community_id,))
        
        members = cursor.fetchall()
        
        for phone_number, prefs_json in members:
            prefs = json.loads(prefs_json)
            
            # Check if user wants alerts of this severity
            if alert.severity.lower() in prefs.get('alert_types', ['high', 'critical']):
                self.queue_notification(phone_number, alert)
        
        conn.close()
        
    def queue_notification(self, phone_number: str, alert: ThreatAlert):
        """Queue notification for delivery"""
        message = f"🚨 SECURITY ALERT: {alert.threat_type.upper()} detected at {alert.location}. Confidence: {alert.confidence:.0%}. Time: {alert.timestamp.strftime('%H:%M')}. Stay alert!"
        
        self.notification_queue.append({
            'phone': phone_number,
            'message': message,
            'timestamp': alert.timestamp,
            'alert_id': alert.alert_id
        })
        
        logger.info(f"Queued notification for {phone_number}")

class SurveillanceCamera:
    """Represents a surveillance camera in the system"""
    
    def __init__(self, camera_id: str, community_id: str, location: str, 
                 video_source: str = None):
        self.camera_id = camera_id
        self.community_id = community_id
        self.location = location
        self.video_source = video_source or 0  # Default to webcam
        self.is_active = False
        self.frame_buffer = deque(maxlen=30)  # Store last 30 frames
        
    def start_capture(self):
        """Start video capture from camera"""
        self.cap = cv2.VideoCapture(self.video_source)
        if not self.cap.isOpened():
            logger.error(f"Cannot open camera {self.camera_id}")
            return False
        
        self.is_active = True
        logger.info(f"Camera {self.camera_id} started successfully")
        return True
    
    def get_frame(self) -> Optional[np.ndarray]:
        """Get current frame from camera"""
        if not self.is_active or not hasattr(self, 'cap'):
            return None
        
        ret, frame = self.cap.read()
        if ret:
            self.frame_buffer.append(frame.copy())
            return frame
        return None
    
    def stop_capture(self):
        """Stop video capture"""
        if hasattr(self, 'cap'):
            self.cap.release()
        self.is_active = False
        logger.info(f"Camera {self.camera_id} stopped")

class QuadrantLoomSecuritySystem:
    """Main surveillance system coordinating all components"""
    
    def __init__(self):
        self.db_manager = DatabaseManager()
        self.threat_model = ThreatDetectionModel()
        self.notification_system = CommunityNotificationSystem(self.db_manager)
        self.cameras: Dict[str, SurveillanceCamera] = {}
        self.is_running = False
        self.alert_cooldown = {}  # Prevent spam alerts
        
    def register_community(self, community_id: str, name: str, location: str,
                          contact_person: str, phone: str, huduma_number: str):
        """Register a new community in the system"""
        conn = sqlite3.connect(self.db_manager.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO communities 
            (id, name, location, contact_person, phone_number, huduma_number)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (community_id, name, location, contact_person, phone, huduma_number))
        
        conn.commit()
        conn.close()
        logger.info(f"Community {name} registered with ID {community_id}")
    
    def add_camera(self, camera_id: str, community_id: str, location: str,
                   video_source: str = None):
        """Add a camera to the surveillance network"""
        camera = SurveillanceCamera(camera_id, community_id, location, video_source)
        
        if camera.start_capture():
            self.cameras[camera_id] = camera
            
            # Add to database
            conn = sqlite3.connect(self.db_manager.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO cameras (id, community_id, location, ip_address)
                VALUES (?, ?, ?, ?)
            ''', (camera_id, community_id, location, video_source or 'local'))
            conn.commit()
            conn.close()
            
            logger.info(f"Camera {camera_id} added to community {community_id}")
            return True
        return False
    
    def create_alert(self, camera_id: str, threat_type: str, confidence: float) -> ThreatAlert:
        """Create a threat alert"""
        camera = self.cameras[camera_id]
        alert_id = hashlib.md5(f"{camera_id}{datetime.now().isoformat()}".encode()).hexdigest()
        
        # Determine severity based on threat type and confidence
        severity = 'LOW'
        if threat_type in ['weapon_detection', 'fire']:
            severity = 'CRITICAL'
        elif threat_type in ['fighting', 'intrusion']:
            severity = 'HIGH'
        elif confidence > 0.9:
            severity = 'HIGH'
        elif confidence > 0.8:
            severity = 'MEDIUM'
        
        alert = ThreatAlert(
            alert_id=alert_id,
            timestamp=datetime.now(),
            threat_type=threat_type,
            confidence=confidence,
            location=camera.location,
            description=f"{threat_type.replace('_', ' ').title()} detected with {confidence:.0%} confidence",
            camera_id=camera_id,
            community_id=camera.community_id,
            severity=severity
        )
        
        # Store alert in database
        conn = sqlite3.connect(self.db_manager.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO alerts 
            (id, community_id, camera_id, threat_type, confidence, severity, description, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (alert.alert_id, alert.community_id, alert.camera_id, alert.threat_type,
              alert.confidence, alert.severity, alert.description, alert.timestamp))
        conn.commit()
        conn.close()
        
        return alert
    
    def should_alert(self, camera_id: str, threat_type: str) -> bool:
        """Check if we should send alert (avoid spam)"""
        key = f"{camera_id}_{threat_type}"
        now = datetime.now()
        
        if key in self.alert_cooldown:
            if now - self.alert_cooldown[key] < timedelta(minutes=5):
                return False
        
        self.alert_cooldown[key] = now
        return True
    
    def process_camera_feed(self, camera_id: str):
        """Process video feed from a specific camera"""
        camera = self.cameras.get(camera_id)
        if not camera:
            return
        
        frame = camera.get_frame()
        if frame is None:
            return
        
        # Detect threats
        threat_type, confidence = self.threat_model.detect_threats(frame)
        
        # If threat detected with high confidence
        if (threat_type != 'normal' and 
            confidence > self.threat_model.confidence_threshold and
            self.should_alert(camera_id, threat_type)):
            
            # Create and send alert
            alert = self.create_alert(camera_id, threat_type, confidence)
            self.notification_system.send_community_alert(alert)
            
            logger.warning(f"THREAT DETECTED: {threat_type} at {camera.location} "
                          f"(Confidence: {confidence:.2f})")
    
    def monitor_all_cameras(self):
        """Main monitoring loop for all cameras"""
        logger.info("Starting surveillance monitoring...")
        self.is_running = True
        
        while self.is_running:
            try:
                # Process each camera
                for camera_id in list(self.cameras.keys()):
                    self.process_camera_feed(camera_id)
                
                # Small delay to prevent excessive CPU usage
                time.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(1)
    
    def start_monitoring(self):
        """Start the surveillance system"""
        if self.cameras:
            monitoring_thread = threading.Thread(target=self.monitor_all_cameras)
            monitoring_thread.daemon = True
            monitoring_thread.start()
            logger.info("Surveillance system started")
        else:
            logger.warning("No cameras registered. Add cameras before starting.")
    
    def stop_monitoring(self):
        """Stop the surveillance system"""
        self.is_running = False
        for camera in self.cameras.values():
            camera.stop_capture()
        logger.info("Surveillance system stopped")
    
    def get_community_alerts(self, community_id: str, hours: int = 24) -> List[Dict]:
        """Get recent alerts for a community"""
        conn = sqlite3.connect(self.db_manager.db_path)
        cursor = conn.cursor()
        
        since = datetime.now() - timedelta(hours=hours)
        cursor.execute('''
            SELECT * FROM alerts 
            WHERE community_id = ? AND timestamp > ?
            ORDER BY timestamp DESC
        ''', (community_id, since))
        
        alerts = []
        for row in cursor.fetchall():
            alerts.append({
                'id': row[0],
                'community_id': row[1],
                'camera_id': row[2],
                'threat_type': row[3],
                'confidence': row[4],
                'severity': row[5],
                'description': row[6],
                'timestamp': row[7],
                'status': row[8]
            })
        
        conn.close()
        return alerts

# Example usage and testing
if __name__ == "__main__":
    # Initialize the system
    security_system = QuadrantLoomSecuritySystem()
    
    # Register a test community
    community_id = "nyumba_kumi_001"
    security_system.register_community(
        community_id=community_id,
        name="Milimani Estate Nyumba Kumi",
        location="Eldoret, Uasin Gishu",
        contact_person="John Kipkoech",
        phone="+254712345678",
        huduma_number="12345678"
    )
    
    # Register community members
    security_system.notification_system.register_community_member(
        community_id=community_id,
        huduma_number="12345679",
        phone_number="+254723456789",
        notification_prefs={"alert_types": ["high", "critical"]}
    )
    
    # Add cameras (using webcam for demo)
    camera_ids = ["cam_001", "cam_002"]
    locations = ["Main Gate", "Parking Area"]
    
    for cam_id, location in zip(camera_ids, locations):
        if security_system.add_camera(cam_id, community_id, location):
            print(f"✅ Camera {cam_id} added at {location}")
        else:
            print(f"❌ Failed to add camera {cam_id}")
    
    # Start monitoring
    if security_system.cameras:
        print("\n🚀 Starting Quadrant Loom Security System...")
        security_system.start_monitoring()
        
        try:
            # Monitor for demo period
            print("📹 Monitoring active. Press Ctrl+C to stop...")
            time.sleep(30)  # Monitor for 30 seconds in demo
            
        except KeyboardInterrupt:
            print("\n⏹️  Stopping surveillance system...")
            security_system.stop_monitoring()
            
        # Show recent alerts
        alerts = security_system.get_community_alerts(community_id)
        print(f"\n📊 Recent alerts for {community_id}: {len(alerts)} alerts")
        for alert in alerts[:5]:  # Show last 5 alerts
            print(f"  - {alert['threat_type']}: {alert['description']}")
    
    print("\n✨ Quadrant Loom Security System Demo Complete!")
    print("🔒 Your community is now safer with AI-powered surveillance!")

"""
Additional Features to Implement:

1. Mobile App Integration:
   - Real-time alerts on mobile devices
   - Community dashboard for viewing alerts
   - Emergency response features
   - Camera status monitoring

2. Advanced AI Features:
   - Face recognition (with privacy controls)
   - License plate recognition
   - Behavioral analysis
   - Predictive analytics

3. IoT Integration:
   - Smart sensors (motion, sound, environmental)
   - Automated lighting control
   - Gate and door automation
   - Integration with existing security systems

4. Cloud Infrastructure:
   - Scalable cloud deployment
   - Real-time data synchronization
   - Backup and disaster recovery
   - Multi-community management

5. Privacy and Compliance:
   - GDPR compliance features
   - Data anonymization
   - Consent management
   - Audit trails

6. Community Features:
   - Voting on security policies
   - Community meetings scheduling
   - Incident reporting
   - Neighborhood watch coordination
"""