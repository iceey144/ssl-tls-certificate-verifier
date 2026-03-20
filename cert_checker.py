import ssl
import socket
from datetime import datetime


def get_certificate(hostname, port=443):
    try:
        print(f"[DEBUG] Connecting to {hostname}:{port}...")
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            print(f"[DEBUG] Socket connected, wrapping with SSL...")
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                print(f"[DEBUG] SSL handshake complete, getting certificate...")
                cert = ssock.getpeercert()
                print(f"[DEBUG] Certificate received successfully")
                return cert
    except Exception as e:
        print(f"[ERROR] Failed to get certificate: {type(e).__name__}: {e}")
        raise


def parse_cert(cert, hostname):
    results = {}

    subject = dict(x[0] for x in cert.get('subject', []))
    results['cn']  = subject.get('commonName', 'N/A')
    results['org'] = subject.get('organizationName', 'N/A')

    issuer = dict(x[0] for x in cert.get('issuer', []))
    results['issuer_cn']  = issuer.get('commonName', 'N/A')
    results['issuer_org'] = issuer.get('organizationName', 'N/A')

    date_format = "%b %d %H:%M:%S %Y %Z"
    not_after  = datetime.strptime(cert['notAfter'],  date_format)
    not_before = datetime.strptime(cert['notBefore'], date_format)
    now = datetime.now()

    results['not_before'] = not_before.strftime('%Y-%m-%d')
    results['not_after']  = not_after.strftime('%Y-%m-%d')
    results['days_left']  = (not_after - now).days
    results['is_expired'] = now > not_after

    sans = [v for (k, v) in cert.get('subjectAltName', [])]
    results['sans'] = sans
    results['host_match'] = any(
        hostname == s or
        (s.startswith('*.') and hostname.endswith(s[1:]))
        for s in sans
    ) or hostname == results['cn']

    if results['is_expired']:
        results['status'] = 'EXPIRED'
    elif not results['host_match']:
        results['status'] = 'HOSTNAME MISMATCH'
    elif results['days_left'] < 30:
        results['status'] = 'EXPIRING SOON'
    else:
        results['status'] = 'VALID'

    return results

def save_report(info, hostname):
    """Save certificate details to a text file."""
    from datetime import datetime as dt
    filename = f"cert_report_{hostname.replace('.', '_')}.txt"
    
    lines = [
        "=" * 50,
        "  SSL/TLS CERTIFICATE VERIFICATION REPORT",
        "=" * 50,
        f"  Domain Checked  : {hostname}",
        f"  Scan Time       : {dt.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Overall Status  : {info['status']}",
        "-" * 50,
        "  SUBJECT",
        f"  Common Name     : {info['cn']}",
        f"  Organization    : {info['org'] or 'N/A'}",
        "-" * 50,
        "  ISSUER",
        f"  Issuer CN       : {info['issuer_cn']}",
        f"  Issuer Org      : {info['issuer_org'] or 'N/A'}",
        "-" * 50,
        "  VALIDITY",
        f"  Valid From      : {info['not_before']}",
        f"  Valid Until     : {info['not_after']}",
        f"  Days Remaining  : {'EXPIRED' if info['is_expired'] else info['days_left']}",
        "-" * 50,
        "  VALIDATION CHECKS",
        f"  Expired         : {'YES ❌' if info['is_expired'] else 'No ✅'}",
        f"  Hostname Match  : {'Yes ✅' if info['host_match'] else 'NO ❌'}",
        "-" * 50,
        f"  SUBJECT ALT NAMES ({len(info['sans'])} total)",
    ]
    
    for san in info['sans']:
        lines.append(f"    {san}")
    
    lines += ["=" * 50, "  End of Report", "=" * 50]
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines))
    
    return filename

if __name__ == "__main__":
    hostname = "google.com"
    print(f"Checking: {hostname}\n")
    try:
        print("[DEBUG] Starting certificate fetch...")
        cert = get_certificate(hostname)
        print("[DEBUG] Parsing certificate...")
        info = parse_cert(cert, hostname)
        print("[DEBUG] Displaying results...\n")
        print(f"  Status      : {info['status']}")
        print(f"  Common Name : {info['cn']}")
        print(f"  Issuer      : {info['issuer_cn']}")
        print(f"  Valid Until : {info['not_after']}")
        print(f"  Days Left   : {info['days_left']}")
        print(f"  Host Match  : {info['host_match']}")
        print(f"  SANs Count  : {len(info['sans'])}")
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user")
    except Exception as e:
        print(f"\n[FATAL] Unexpected error: {e}")
        import traceback
        traceback.print_exc()