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
        """Scan for available networks and analyze security"""
        try:
            print("Starting network scan and security analysis...")
            self.iface.scan()
            time.sleep(4)  # Increased wait time for scan to complete
            
            networks = []
            for network in self.iface.scan_results():
                if network.ssid.strip():  # Skip networks with empty SSID
                    signal_strength = 2 * (100 + network.signal)  # Convert to percentage
                    signal_strength = max(0, min(100, signal_strength))  # Clamp between 0-100
                    
                    # Get security info including vulnerabilities
                    security_info = self._get_security_type(network)
                    
                    networks.append({
                        'ssid': network.ssid.strip(),
                        'bssid': network.bssid if hasattr(network, 'bssid') else 'Unknown',
                        'signal': signal_strength,
                        'security': security_info['type'],
                        'vulnerabilities': security_info['vulnerabilities'],
                        'risk_level': security_info['risk_level'],
                        'recommendations': security_info['recommendations'],
                        'security_info': security_info  # Include full security info
                    })
            
            print(f"Found {len(networks)} networks")
            if not networks:
                print("No networks found - this might indicate scanning issues")
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
        """Get network security type and vulnerabilities with enhanced analysis"""
        try:
            security_info = {
                'type': 'Unknown',
                'vulnerabilities': [],
                'risk_level': 'Unknown',
                'recommendations': [],
                'advanced_analysis': {}
            }

            # Original security type analysis
            akm_types = []
            if hasattr(network, 'akm'):
                akm_types = network.akm if isinstance(network.akm, list) else [network.akm]
            
            cipher_types = []
            if hasattr(network, 'cipher'):
                cipher_types = network.cipher if isinstance(network.cipher, list) else [network.cipher]

            # Perform advanced analysis
            mac_analysis = self.analyze_mac_spoofing(network)
            traffic_analysis = self.analyze_network_traffic(network)
            wps_analysis = self.check_wps_vulnerability(network)
            channel_analysis = self.analyze_channel_interference(network)
            rogue_analysis = self.detect_rogue_access_points(network)

            # Add advanced analysis results
            security_info['advanced_analysis'] = {
                'mac_spoofing': mac_analysis,
                'traffic': traffic_analysis,
                'wps': wps_analysis,
                'channel': channel_analysis,
                'rogue_detection': rogue_analysis
            }

            # Update risk level based on all analyses
            risk_levels = {
                'Critical': 4,
                'High': 3,
                'Medium': 2,
                'Low': 1,
                'Unknown': 0
            }

            max_risk = max(
                risk_levels[mac_analysis['risk_level']],
                risk_levels[traffic_analysis['risk_level']],
                risk_levels[wps_analysis['risk_level']],
                risk_levels[channel_analysis['risk_level']],
                risk_levels[rogue_analysis['risk_level']]
            )

            # Convert numeric risk back to string
            security_info['risk_level'] = next(
                level for level, value in risk_levels.items() 
                if value == max_risk
            )

            # Combine all vulnerabilities
            security_info['vulnerabilities'].extend(mac_analysis['indicators'])
            security_info['vulnerabilities'].extend(traffic_analysis['active_threats'])
            security_info['vulnerabilities'].extend(wps_analysis['vulnerabilities'])
            if channel_analysis['has_interference']:
                security_info['vulnerabilities'].extend([
                    f"Channel interference detected on channel {getattr(network, 'channel', 'unknown')}"
                ])
            security_info['vulnerabilities'].extend(rogue_analysis['indicators'])

            # Add recommendations
            if mac_analysis['is_spoofed']:
                security_info['recommendations'].append('Verify AP MAC address authenticity')
            if traffic_analysis['attacks_detected']:
                security_info['recommendations'].append('Investigate suspicious network traffic')
            if wps_analysis['is_vulnerable']:
                security_info['recommendations'].append('Disable WPS or upgrade to version 2.0+')
            security_info['recommendations'].extend(channel_analysis['recommendations'])
            if rogue_analysis['is_rogue']:
                security_info['recommendations'].append('Investigate potential rogue access points')

            return security_info

        except Exception as e:
            print(f"Error in enhanced security analysis: {str(e)}")
            return {
                'type': 'Unknown',
                'vulnerabilities': [f'Error in security analysis: {str(e)}'],
                'risk_level': 'Unknown',
                'recommendations': ['Perform manual security audit'],
                'advanced_analysis': {}
            }

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

    def analyze_mac_spoofing(self, network):
        """Detect potential MAC address spoofing"""
        try:
            mac_info = {
                'is_spoofed': False,
                'risk_level': 'Low',
                'indicators': [],
                'details': {}
            }
            
            if hasattr(network, 'bssid'):
                mac = network.bssid.lower()
                # Check for common default MACs
                if mac.startswith(('00:11:22', '12:34:56', 'aa:bb:cc')):
                    mac_info['is_spoofed'] = True
                    mac_info['risk_level'] = 'High'
                    mac_info['indicators'].append('Default/Generic MAC pattern detected')
                
                # Check for invalid MAC formats
                if not all(c in '0123456789abcdef:' for c in mac):
                    mac_info['is_spoofed'] = True
                    mac_info['risk_level'] = 'Critical'
                    mac_info['indicators'].append('Invalid MAC address format')
                
                # Check vendor prefix
                vendor_prefix = mac[:8]
                if vendor_prefix in ['00:00:00', 'ff:ff:ff']:
                    mac_info['is_spoofed'] = True
                    mac_info['risk_level'] = 'High'
                    mac_info['indicators'].append('Invalid vendor prefix')
                
                mac_info['details']['vendor_prefix'] = vendor_prefix
                mac_info['details']['original_mac'] = mac
            
            return mac_info
        except Exception as e:
            print(f"Error analyzing MAC spoofing: {str(e)}")
            return {
                'is_spoofed': False,
                'risk_level': 'Unknown',
                'indicators': [f'Error analyzing MAC: {str(e)}'],
                'details': {}
            }

    def analyze_network_traffic(self, network):
        """Analyze network traffic for active attacks"""
        try:
            traffic_info = {
                'attacks_detected': False,
                'risk_level': 'Low',
                'active_threats': [],
                'statistics': {}
            }
            
            if hasattr(network, 'stats'):
                # Check for abnormal traffic patterns
                if network.stats.get('deauth_packets', 0) > 10:
                    traffic_info['attacks_detected'] = True
                    traffic_info['risk_level'] = 'Critical'
                    traffic_info['active_threats'].append('Deauthentication Attack in Progress')
                
                if network.stats.get('auth_failures', 0) > 20:
                    traffic_info['attacks_detected'] = True
                    traffic_info['risk_level'] = 'High'
                    traffic_info['active_threats'].append('Potential Brute Force Attack')
                
                # Record traffic statistics
                traffic_info['statistics'] = {
                    'packets_per_second': network.stats.get('pps', 0),
                    'data_rate': network.stats.get('data_rate', 0),
                    'retry_rate': network.stats.get('retry_rate', 0)
                }
            
            return traffic_info
        except Exception as e:
            print(f"Error analyzing network traffic: {str(e)}")
            return {
                'attacks_detected': False,
                'risk_level': 'Unknown',
                'active_threats': [f'Error analyzing traffic: {str(e)}'],
                'statistics': {}
            }

    def check_wps_vulnerability(self, network):
        """Check for WPS vulnerabilities"""
        try:
            wps_info = {
                'is_vulnerable': False,
                'risk_level': 'Low',
                'vulnerabilities': [],
                'config': {}
            }
            
            if hasattr(network, 'wps'):
                wps_info['config']['enabled'] = network.wps.get('enabled', False)
                wps_info['config']['locked'] = network.wps.get('locked', False)
                wps_info['config']['version'] = network.wps.get('version', 'unknown')
                
                # Check WPS version vulnerabilities
                if wps_info['config']['enabled']:
                    if wps_info['config']['version'] < '2.0':
                        wps_info['is_vulnerable'] = True
                        wps_info['risk_level'] = 'Critical'
                        wps_info['vulnerabilities'].append('WPS < 2.0 vulnerable to Pixie Dust attack')
                    
                    if not wps_info['config']['locked']:
                        wps_info['is_vulnerable'] = True
                        wps_info['risk_level'] = 'High'
                        wps_info['vulnerabilities'].append('WPS not locked - vulnerable to brute force')
            
            return wps_info
        except Exception as e:
            print(f"Error checking WPS vulnerability: {str(e)}")
            return {
                'is_vulnerable': False,
                'risk_level': 'Unknown',
                'vulnerabilities': [f'Error checking WPS: {str(e)}'],
                'config': {}
            }

    def analyze_channel_interference(self, network):
        """Analyze WiFi channel interference"""
        try:
            channel_info = {
                'has_interference': False,
                'risk_level': 'Low',
                'interference_sources': [],
                'recommendations': []
            }
            
            if hasattr(network, 'channel'):
                current_channel = network.channel
                # Check for overlapping channels
                overlapping = []
                for other_network in self.iface.scan_results():
                    if other_network.channel in range(current_channel - 2, current_channel + 3):
                        if other_network.ssid != network.ssid:
                            overlapping.append({
                                'ssid': other_network.ssid,
                                'channel': other_network.channel,
                                'signal': other_network.signal
                            })
                
                if overlapping:
                    channel_info['has_interference'] = True
                    channel_info['risk_level'] = 'Medium'
                    channel_info['interference_sources'] = overlapping
                    channel_info['recommendations'].append(
                        f'Consider switching to a less crowded channel'
                    )
                
                # Check for non-standard channel width
                if hasattr(network, 'channel_width'):
                    if network.channel_width > 40:
                        channel_info['has_interference'] = True
                        channel_info['risk_level'] = 'Medium'
                        channel_info['interference_sources'].append({
                            'type': 'Wide Channel',
                            'width': f'{network.channel_width}MHz'
                        })
                        channel_info['recommendations'].append(
                            'Consider using standard 20/40MHz channel width'
                        )
            
            return channel_info
        except Exception as e:
            print(f"Error analyzing channel interference: {str(e)}")
            return {
                'has_interference': False,
                'risk_level': 'Unknown',
                'interference_sources': [f'Error analyzing interference: {str(e)}'],
                'recommendations': ['Perform manual channel analysis']
            }

    def detect_rogue_access_points(self, network):
        """Detect potential rogue access points"""
        try:
            rogue_info = {
                'is_rogue': False,
                'risk_level': 'Low',
                'indicators': [],
                'similar_networks': []
            }
            
            if hasattr(network, 'ssid') and hasattr(network, 'bssid'):
                # Check for similar SSIDs
                for other in self.iface.scan_results():
                    if other.ssid != network.ssid and other.bssid != network.bssid:
                        # Calculate string similarity
                        similarity = self._calculate_ssid_similarity(network.ssid, other.ssid)
                        if similarity > 0.8:  # 80% similar
                            rogue_info['is_rogue'] = True
                            rogue_info['risk_level'] = 'High'
                            rogue_info['indicators'].append('Similar SSID detected')
                            rogue_info['similar_networks'].append({
                                'ssid': other.ssid,
                                'bssid': other.bssid,
                                'similarity': similarity
                            })
                
                # Check for unusual signal patterns
                if hasattr(network, 'signal'):
                    signal_strength = 2 * (100 + network.signal)
                    if signal_strength > 90:
                        rogue_info['is_rogue'] = True
                        rogue_info['risk_level'] = 'High'
                        rogue_info['indicators'].append('Unusually strong signal')
            
            return rogue_info
        except Exception as e:
            print(f"Error detecting rogue access points: {str(e)}")
            return {
                'is_rogue': False,
                'risk_level': 'Unknown',
                'indicators': [f'Error detecting rogue APs: {str(e)}'],
                'similar_networks': []
            }

    def _calculate_ssid_similarity(self, ssid1, ssid2):
        """Calculate similarity between two SSIDs"""
        try:
            # Simple Levenshtein distance implementation
            if len(ssid1) < len(ssid2):
                return self._calculate_ssid_similarity(ssid2, ssid1)

            if len(ssid2) == 0:
                return 0.0

            previous_row = range(len(ssid2) + 1)
            for i, c1 in enumerate(ssid1):
                current_row = [i + 1]
                for j, c2 in enumerate(ssid2):
                    insertions = previous_row[j + 1] + 1
                    deletions = current_row[j] + 1
                    substitutions = previous_row[j] + (c1 != c2)
                    current_row.append(min(insertions, deletions, substitutions))
                previous_row = current_row

            # Convert distance to similarity score (0-1)
            max_len = max(len(ssid1), len(ssid2))
            similarity = 1 - (previous_row[-1] / max_len)
            return similarity
        except Exception as e:
            print(f"Error calculating SSID similarity: {str(e)}")
            return 0.0