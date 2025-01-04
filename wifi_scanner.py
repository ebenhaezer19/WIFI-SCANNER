import pywifi
from pywifi import const
import time
import json

class WiFiScanner:
    def __init__(self):
        try:
            self.wifi = pywifi.PyWiFi()
            self.iface = self.wifi.interfaces()[0]
            if not self.iface:
                raise Exception("No wireless interface found")
        except Exception as e:
            print(f"Initialization error: {str(e)}")
            return {'success': False, 'error': str(e)}

    def scan(self):
        try:
            # Enable the interface
            if self.iface.status() in [const.IFACE_DISCONNECTED, const.IFACE_INACTIVE]:
                self.iface.disconnect()
                time.sleep(1)
                
            # Perform the scan
            self.iface.scan()
            time.sleep(4)  
            
            results = []
            scan_results = self.iface.scan_results()
            
            if not scan_results:
                return {'success': True, 'networks': [], 'message': 'No networks found'}
            
            for network in scan_results:
                if network.ssid.strip():
                    try:
                        signal_strength = 2 * (100 + getattr(network, 'signal', -100))
                        signal_strength = max(0, min(100, signal_strength))
                        
                        results.append({
                            'ssid': network.ssid.strip(),
                            'strength': signal_strength,
                            'security': self._get_security_type(network)
                        })
                    except Exception as e:
                        print(f"Error processing network {network.ssid}: {str(e)}")
                        continue
            
            return {'success': True, 'networks': results}
            
        except Exception as e:
            print(f"Scan error: {str(e)}")
            return {'success': False, 'error': str(e)}

    def _get_security_type(self, network):
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

    def try_password(self, ssid, password):
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
            time.sleep(5)  # Increased wait time for connection attempt
            
            connected = self.iface.status() == const.IFACE_CONNECTED
            return {'success': connected, 'message': 'Connected successfully' if connected else 'Failed to connect'}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}