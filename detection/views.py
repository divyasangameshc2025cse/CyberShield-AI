"""
Views for AI-Based Cyber Threat Detection in Unidirectional IP Traffic.
"""

import os
import joblib
import pandas as pd
import numpy as np
from django.shortcuts import render
from django.conf import settings

# Global ML model and preprocessor cache
_MODEL = None
_PREPROCESSOR = None
_MODEL_LOAD_ERROR = None

def get_ml_pipeline():
    """
    Safely load and cache the pre-trained ML model and preprocessor.
    """
    global _MODEL, _PREPROCESSOR, _MODEL_LOAD_ERROR

    if _MODEL is not None and _PREPROCESSOR is not None:
        return _MODEL, _PREPROCESSOR, None

    try:
        # Determine model paths with fallback to Cyber_Threat directory
        model_path = getattr(settings, 'MODEL_PATH', None)
        preprocessor_path = getattr(settings, 'PREPROCESSOR_PATH', None)

        if not model_path or not os.path.exists(model_path):
            model_path = os.path.join(settings.BASE_DIR, 'Cyber_Threat', 'cyber_threat_detection_model.pkl')
        
        if not preprocessor_path or not os.path.exists(preprocessor_path):
            preprocessor_path = os.path.join(settings.BASE_DIR, 'Cyber_Threat', 'cyber_threat_preprocessor.pkl')

        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found at: {model_path}")
        if not os.path.exists(preprocessor_path):
            raise FileNotFoundError(f"Preprocessor file not found at: {preprocessor_path}")

        _PREPROCESSOR = joblib.load(preprocessor_path)
        _MODEL = joblib.load(model_path)
        _MODEL_LOAD_ERROR = None

        return _MODEL, _PREPROCESSOR, None
    except Exception as exc:
        _MODEL_LOAD_ERROR = str(exc)
        return None, None, _MODEL_LOAD_ERROR


# Metadata for the 19 features required by the preprocessor
FEATURE_CONFIG = [
    # Categorical Features
    {
        'name': 'proto',
        'label': 'Network Protocol (proto)',
        'type': 'select',
        'category': 'connection',
        'help': 'Transport or network protocol used in the unidirectional IP stream.',
        'options': [
            'tcp', 'udp', 'icmp', 'arp', 'ospf', 'sctp', 'gre', 'igmp', 'ip',
            'ipv6', 'rsvp', 'vrrp', 'unas', 'swipe', 'sun-nd', 'mobile', 'pim'
        ],
        'default': 'tcp'
    },
    {
        'name': 'service',
        'label': 'Application Service (service)',
        'type': 'select',
        'category': 'connection',
        'help': 'Destination application service or protocol.',
        'options': ['-', 'http', 'dns', 'ftp', 'ftp-data', 'smtp', 'ssh', 'irc', 'pop3', 'radius', 'snmp', 'ssl', 'dhcp'],
        'default': 'http'
    },
    {
        'name': 'state',
        'label': 'Transaction State (state)',
        'type': 'select',
        'category': 'connection',
        'help': 'Connection state indicators (e.g. FIN = Finished, INT = Interactive, CON = Connected).',
        'options': ['FIN', 'INT', 'CON', 'REQ', 'RST', 'ECO', 'PAR', 'URN', 'no'],
        'default': 'FIN'
    },

    # Numerical Features - Duration & Rates
    {
        'name': 'dur',
        'label': 'Flow Duration (dur)',
        'type': 'number',
        'category': 'timing',
        'unit': 'sec',
        'step': '0.000001',
        'min': '0',
        'help': 'Total connection record duration in seconds.',
        'default': 0.121478
    },
    {
        'name': 'rate',
        'label': 'Packet Transmission Rate (rate)',
        'type': 'number',
        'category': 'timing',
        'unit': 'pkts/s',
        'step': '0.001',
        'min': '0',
        'help': 'Rate of packets transmitted per second.',
        'default': 74.087
    },
    {
        'name': 'sinpkt',
        'label': 'Source Inter-Packet Time (sinpkt)',
        'type': 'number',
        'category': 'timing',
        'unit': 'mSec',
        'step': '0.001',
        'min': '0',
        'help': 'Source interpacket arrival time in milliseconds.',
        'default': 24.295
    },
    {
        'name': 'dinpkt',
        'label': 'Destination Inter-Packet Time (dinpkt)',
        'type': 'number',
        'category': 'timing',
        'unit': 'mSec',
        'step': '0.001',
        'min': '0',
        'help': 'Destination interpacket arrival time in milliseconds.',
        'default': 40.492
    },
    {
        'name': 'sjit',
        'label': 'Source Jitter (sjit)',
        'type': 'number',
        'category': 'timing',
        'unit': 'mSec',
        'step': '0.001',
        'min': '0',
        'help': 'Source jitter in milliseconds.',
        'default': 10.0
    },
    {
        'name': 'djit',
        'label': 'Destination Jitter (djit)',
        'type': 'number',
        'category': 'timing',
        'unit': 'mSec',
        'step': '0.001',
        'min': '0',
        'help': 'Destination jitter in milliseconds.',
        'default': 5.0
    },

    # Numerical Features - Bytes and Bandwidth
    {
        'name': 'sbytes',
        'label': 'Source-to-Dest Bytes (sbytes)',
        'type': 'number',
        'category': 'bandwidth',
        'unit': 'bytes',
        'step': '1',
        'min': '0',
        'help': 'Total bytes transferred from source to destination.',
        'default': 258
    },
    {
        'name': 'dbytes',
        'label': 'Dest-to-Source Bytes (dbytes)',
        'type': 'number',
        'category': 'bandwidth',
        'unit': 'bytes',
        'step': '1',
        'min': '0',
        'help': 'Total bytes transferred from destination to source.',
        'default': 172
    },
    {
        'name': 'sload',
        'label': 'Source Bit Rate (sload)',
        'type': 'number',
        'category': 'bandwidth',
        'unit': 'bps',
        'step': '0.01',
        'min': '0',
        'help': 'Source bits per second.',
        'default': 14158.94
    },
    {
        'name': 'dload',
        'label': 'Destination Bit Rate (dload)',
        'type': 'number',
        'category': 'bandwidth',
        'unit': 'bps',
        'step': '0.01',
        'min': '0',
        'help': 'Destination bits per second.',
        'default': 8495.36
    },
    {
        'name': 'response_body_len',
        'label': 'HTTP Response Body Length (response_body_len)',
        'type': 'number',
        'category': 'bandwidth',
        'unit': 'bytes',
        'step': '1',
        'min': '0',
        'help': 'Actual uncompressed content size of HTTP response message.',
        'default': 0
    },

    # Numerical Features - TCP Connection & RTT
    {
        'name': 'stcpb',
        'label': 'Source TCP Base Sequence (stcpb)',
        'type': 'number',
        'category': 'tcp',
        'unit': 'seq',
        'step': '1',
        'min': '0',
        'help': 'Source TCP base sequence number.',
        'default': 621772692
    },
    {
        'name': 'dtcpb',
        'label': 'Destination TCP Base Sequence (dtcpb)',
        'type': 'number',
        'category': 'tcp',
        'unit': 'seq',
        'step': '1',
        'min': '0',
        'help': 'Destination TCP base sequence number.',
        'default': 220197724
    },
    {
        'name': 'tcprtt',
        'label': 'TCP Round Trip Time (tcprtt)',
        'type': 'number',
        'category': 'tcp',
        'unit': 'sec',
        'step': '0.000001',
        'min': '0',
        'help': 'TCP connection setup round-trip time (synack + ackdat).',
        'default': 0.000955
    },
    {
        'name': 'synack',
        'label': 'TCP SYN-ACK Time (synack)',
        'type': 'number',
        'category': 'tcp',
        'unit': 'sec',
        'step': '0.000001',
        'min': '0',
        'help': 'Time elapsed between SYN and SYN_ACK packet.',
        'default': 0.000577
    },
    {
        'name': 'ackdat',
        'label': 'TCP ACK-DAT Time (ackdat)',
        'type': 'number',
        'category': 'tcp',
        'unit': 'sec',
        'step': '0.000001',
        'min': '0',
        'help': 'Time elapsed between SYN_ACK and ACK packet.',
        'default': 0.000378
    },
]


def index(request):
    """
    Renders the cybersecurity homepage.
    """
    return render(request, 'detection/index.html', {
        'page': 'home'
    })


def about(request):
    """
    Renders the About Project section/page.
    """
    return render(request, 'detection/index.html', {
        'page': 'about',
        'scroll_to_about': True
    })


def detect_threat(request):
    """
    Handles traffic feature input form (GET) and machine learning classification (POST).
    """
    model, preprocessor, load_error = get_ml_pipeline()

    if load_error:
        return render(request, 'detection/detection.html', {
            'page': 'detect',
            'features': FEATURE_CONFIG,
            'error_message': f"Model Initialization Error: {load_error}. Please ensure model files are present."
        })

    if request.method == 'POST':
        raw_values = {}
        processed_input = {}
        validation_errors = []

        # Process each feature
        for feat in FEATURE_CONFIG:
            field_name = feat['name']
            val = request.POST.get(field_name, '').strip()
            raw_values[field_name] = val

            if val == '' and feat['type'] == 'number':
                validation_errors.append(f"Missing required numeric value for '{feat['label']}'")
                continue

            if feat['type'] == 'number':
                try:
                    # Parse as float or int
                    num_val = float(val)
                    if num_val < 0:
                        validation_errors.append(f"Value for '{feat['label']}' cannot be negative.")
                    processed_input[field_name] = num_val
                except ValueError:
                    validation_errors.append(f"Invalid numeric input for '{feat['label']}': '{val}'")
            else:
                processed_input[field_name] = val

        if validation_errors:
            return render(request, 'detection/detection.html', {
                'page': 'detect',
                'features': FEATURE_CONFIG,
                'form_data': raw_values,
                'error_message': validation_errors[0]
            })

        try:
            # Build 1-row DataFrame matching the exact expected input format
            input_df = pd.DataFrame([processed_input])

            # Apply trained ColumnTransformer preprocessor
            transformed_features = preprocessor.transform(input_df)

            # Predict threat classification (0 = Normal, 1 = Attack)
            prediction_class = int(model.predict(transformed_features)[0])

            # Calculate confidence probability if supported
            confidence = None
            prob_normal = None
            prob_attack = None

            if hasattr(model, 'predict_proba'):
                probabilities = model.predict_proba(transformed_features)[0]
                # classes_ is [0, 1] -> [Normal, Attack]
                prob_normal = round(float(probabilities[0]) * 100, 2)
                prob_attack = round(float(probabilities[1]) * 100, 2)
                confidence = round(float(probabilities[prediction_class]) * 100, 2)

            if prediction_class == 1:
                prediction_label = "ATTACK DETECTED"
                status = "ATTACK"
                status_class = "threat-attack"
                badge_text = "MALICIOUS TRAFFIC DETECTED"
                summary_text = "The AI detection model identified malicious traffic patterns consistent with cyber threats or intrusive network behaviors."
                recommendation = "Immediate Action Recommended: Quarantine sender IP, inspect packet payloads, and log network socket activity for deep forensic analysis."
            else:
                prediction_label = "NORMAL"
                status = "NORMAL"
                status_class = "threat-normal"
                badge_text = "BENIGN NETWORK TRAFFIC"
                summary_text = "The AI detection model classified this unidirectional IP stream as legitimate, standard network traffic."
                recommendation = "No security anomaly detected. The traffic session conforms to standard RFC protocol specifications."

            # Organize feature summary table for result display
            feature_summary = []
            for feat in FEATURE_CONFIG:
                feature_summary.append({
                    'name': feat['name'],
                    'label': feat['label'],
                    'value': processed_input.get(feat['name']),
                    'unit': feat.get('unit', '')
                })

            context = {
                'page': 'result',
                'prediction_label': prediction_label,
                'status': status,
                'status_class': status_class,
                'badge_text': badge_text,
                'confidence': confidence,
                'prob_normal': prob_normal,
                'prob_attack': prob_attack,
                'summary_text': summary_text,
                'recommendation': recommendation,
                'feature_summary': feature_summary,
                'raw_input': processed_input
            }

            return render(request, 'detection/result.html', context)

        except Exception as exc:
            return render(request, 'detection/detection.html', {
                'page': 'detect',
                'features': FEATURE_CONFIG,
                'form_data': raw_values,
                'error_message': f"Prediction Processing Error: {str(exc)}"
            })

    # GET request - render the form
    return render(request, 'detection/detection.html', {
        'page': 'detect',
        'features': FEATURE_CONFIG
    })


def result_view(request):
    """
    Renders the result page (or fallback placeholder if accessed directly).
    """
    return render(request, 'detection/result.html', {
        'page': 'result'
    })

