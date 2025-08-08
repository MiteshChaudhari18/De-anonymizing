import requests
import socket
import os
from typing import Optional, Dict, Any
import time

class TorConnector:
    """Handles Tor proxy connections and validation"""
    
    def __init__(self):
        self.proxy_host = os.getenv('TOR_PROXY_HOST', '127.0.0.1')
        self.proxy_port = int(os.getenv('TOR_PROXY_PORT', '9050'))
        self.control_port = int(os.getenv('TOR_CONTROL_PORT', '9051'))
        self.timeout = int(os.getenv('TOR_TIMEOUT', '30'))
        
        # Proxy configuration for requests
        self.proxies = {
            'http': f'socks5h://{self.proxy_host}:{self.proxy_port}',
            'https': f'socks5h://{self.proxy_host}:{self.proxy_port}'
        }
        
        # Test endpoints
        self.test_endpoints = [
            'https://check.torproject.org/api/ip',
            'https://httpbin.org/ip'
        ]
    
    def check_connection(self) -> bool:
        """Check if Tor proxy is accessible and working"""
        try:
            # First check if port is open
            if not self._check_port_open():
                return False
            
            # Test with a simple request
            return self._test_proxy_request()
            
        except Exception as e:
            print(f"Tor connection check failed: {e}")
            return False
    
    def _check_port_open(self) -> bool:
        """Check if Tor proxy port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.proxy_host, self.proxy_port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _test_proxy_request(self) -> bool:
        """Test proxy with actual HTTP request"""
        try:
            response = requests.get(
                'https://check.torproject.org/api/ip',
                proxies=self.proxies,
                timeout=self.timeout,
                headers=self._get_headers()
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('IsTor', False)
            
            return False
            
        except Exception as e:
            print(f"Proxy test request failed: {e}")
            return False
    
    def get_session(self) -> requests.Session:
        """Get a requests session configured for Tor"""
        session = requests.Session()
        session.proxies.update(self.proxies)
        session.headers.update(self._get_headers())
        return session
    
    def _get_headers(self) -> Dict[str, str]:
        """Get standard headers for requests"""
        return {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
    
    def get_ip_info(self) -> Optional[Dict[str, Any]]:
        """Get current IP information through Tor"""
        try:
            session = self.get_session()
            response = session.get(
                'https://httpbin.org/ip',
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json()
            
            return None
            
        except Exception as e:
            print(f"Failed to get IP info: {e}")
            return None
    
    def new_identity(self) -> bool:
        """Request new Tor identity (requires control port access)"""
        try:
            import stem.control
            
            with stem.control.Controller.from_port(port=self.control_port) as controller:
                controller.authenticate()
                controller.signal(stem.Signal.NEWNYM)
                
                # Wait for new circuit
                time.sleep(5)
                return True
                
        except ImportError:
            print("stem library not available for identity renewal")
            return False
        except Exception as e:
            print(f"Failed to get new identity: {e}")
            return False
    
    def get_circuit_info(self) -> Optional[Dict[str, Any]]:
        """Get current Tor circuit information"""
        try:
            import stem.control
            
            with stem.control.Controller.from_port(port=self.control_port) as controller:
                controller.authenticate()
                
                circuits = []
                for circuit in controller.get_circuits():
                    circuits.append({
                        'id': circuit.id,
                        'status': circuit.status.name,
                        'path': [f"{relay.nickname} ({relay.fingerprint[:8]})" 
                                for relay in circuit.path],
                        'build_flags': circuit.build_flags,
                        'purpose': circuit.purpose
                    })
                
                return {'circuits': circuits, 'count': len(circuits)}
                
        except ImportError:
            print("stem library not available for circuit info")
            return None
        except Exception as e:
            print(f"Failed to get circuit info: {e}")
            return None
