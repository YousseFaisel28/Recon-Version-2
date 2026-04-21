import sublist3r
import traceback
import re
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

# ====================================================
# MONKEY PATCH: Fix CSRF token and response type bugs in sublist3r
# ====================================================
def patched_get_csrftoken(self, resp):
    """Fixed version of get_csrftoken that handles missing tokens and int responses."""
    # Bug fix: if resp is an int (error code 0), findall will fail
    if not isinstance(resp, (str, bytes)):
        raise ValueError(f"Invalid response type: {type(resp)}")
    
    # Try multiple CSRF token patterns
    patterns = [
        r'<input type="hidden" name="csrfmiddlewaretoken" value="(.*?)">',
        r'<input name="csrfmiddlewaretoken" type="hidden" value="(.*?)">',
        r'name="csrfmiddlewaretoken"\s+value="(.*?)"',
        r'csrfmiddlewaretoken["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        r'csrf[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
    ]
    
    for pattern in patterns:
        try:
            csrf_regex = re.compile(pattern, re.S | re.I)
            matches = csrf_regex.findall(resp)
            if matches:
                token = matches[0].strip()
                if token:
                    return token
        except:
            continue
    
    raise ValueError("CSRF token not found in response")

def patched_enumerate(self):
    """Improved enumerate with better error handling and parallel checking."""
    self.lock = threading.BoundedSemaphore(value=70)
    try:
        # Check if req method exists (specific to DNSdumpster and some others)
        if hasattr(self, 'req'):
            resp = self.req('GET', self.base_url)
        else:
            return self.live_subdomains

        token = self.get_csrftoken(resp)
    except Exception as e:
        if self.verbose:
            self.print_(f"{self.engine_name}: Engine skipped due to: {str(e)}")
        return self.live_subdomains
    
    params = {'csrfmiddlewaretoken': token, 'targetip': self.domain}
    try:
        if hasattr(self, 'req'):
            post_resp = self.req('POST', self.base_url, params)
            if post_resp:
                self.extract_domains(post_resp)
    except:
        pass
    
    # Parallel host checking (fixing the sequential join bug)
    threads = []
    for subdomain in self.subdomains:
        t = threading.Thread(target=self.check_host, args=(subdomain,))
        t.setDaemon(True)
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join(timeout=2) # Don't hang forever
        
    return self.live_subdomains

# Apply patches to engines that have the problematic CSRF methods
for engine_name in ['DNSdumpster', 'Netcraft']:
    if hasattr(sublist3r, engine_name):
        cls = getattr(sublist3r, engine_name)
        if hasattr(cls, 'get_csrftoken'):
            cls.get_csrftoken = patched_get_csrftoken
        if hasattr(cls, 'enumerate'):
            cls.enumerate = patched_enumerate

# Apply the monkey patches to DNSdumpster class
if hasattr(sublist3r, 'DNSdumpster'):
    sublist3r.DNSdumpster.get_csrftoken = patched_get_csrftoken
    sublist3r.DNSdumpster.enumerate = patched_enumerate

# Global executor for background tasks
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="sublist3r")

def run_sublist3r(domain, timeout=300):
    """
    Run Sublist3r to enumerate subdomains in the background efficiently.
    Returns a future object immediately - does NOT block!
    Use future.result() or future.done() to check/get results.
    """
    def _run_sublist3r():
        """Internal function to run Sublist3r with comprehensive error handling."""
        try:
            subdomains = sublist3r.main(
                domain, 
                40, 
                savefile=None, 
                ports=None, 
                silent=True, 
                verbose=False, 
                enable_bruteforce=False, 
                engines=None
            )
            # Handle case where sublist3r returns None or empty list
            if subdomains is None:
                subdomains = []
            return {"status": "success", "subdomains": list(set(subdomains))}  # Remove duplicates
        except IndexError as e:
            # Common error: CSRF token extraction failure or similar parsing issues
            error_msg = f"Sublist3r parsing error (likely website structure changed): {str(e)}"
            print(f"[Sublist3r] {error_msg}")
            return {"status": "error", "error": error_msg, "subdomains": [], "error_type": "IndexError"}
        except (KeyError, AttributeError) as e:
            # Parsing/parsing structure errors
            error_msg = f"Sublist3r parsing error: {str(e)}"
            print(f"[Sublist3r] {error_msg}")
            return {"status": "error", "error": error_msg, "subdomains": [], "error_type": type(e).__name__}
        except Exception as e:
            # Catch all other exceptions with full traceback for debugging
            error_msg = f"Sublist3r error: {str(e)}"
            error_type = type(e).__name__
            print(f"[Sublist3r] {error_msg}")
            print(f"[Sublist3r] Error type: {error_type}")
            # Print traceback for debugging (can be removed in production)
            traceback.print_exc()
            return {"status": "error", "error": error_msg, "subdomains": [], "error_type": error_type}
    
    # Submit task to thread pool (runs in background - returns immediately!)
    future = _executor.submit(_run_sublist3r)
    return future


def get_sublist3r_result(future, timeout=None):
    """
    Get the result from a sublist3r future.
    If timeout is None, waits indefinitely. Otherwise waits up to timeout seconds.
    """
    try:
        if timeout is None:
            result = future.result()
        else:
            result = future.result(timeout=timeout)
        return result
    except FutureTimeoutError:
        print(f"[Sublist3r] Operation timed out after {timeout} seconds")
        return {"status": "timeout", "subdomains": [], "error": f"Operation timed out after {timeout} seconds"}
    except Exception as e:
        error_msg = f"Failed to get sublist3r result: {str(e)}"
        print(f"[Sublist3r] {error_msg}")
        traceback.print_exc()
        return {"status": "error", "error": error_msg, "subdomains": [], "error_type": type(e).__name__}


def run_sublist3r_blocking(domain, timeout=300):
    """
    Run Sublist3r and wait for result (blocking version).
    Use this if you need to wait for the result immediately.
    """
    future = run_sublist3r(domain)
    return get_sublist3r_result(future, timeout=timeout)

