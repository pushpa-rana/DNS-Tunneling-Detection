import time
from typing import Dict, List, Optional, Any
import dns.resolver
import dns.rdatatype
from app.config import settings

def resolve_dns_records(hostname: str, timeout: float = None) -> Dict[str, Any]:
    """
    Safely resolves public DNS records (A, AAAA, MX, NS, TXT, CNAME) for the given hostname.
    Extracts explicit answer values, TTLs, and standard RFC RCODE status.
    Lookup failure is NOT treated as proof of maliciousness.
    """
    if timeout is None:
        timeout = settings.DNS_ENRICHMENT_TIMEOUT_SEC

    start_time = time.time()
    results: Dict[str, List[Dict[str, Any]]] = {}
    resolver_status = "UNKNOWN"
    query_error: Optional[str] = None
    nameservers_used = []

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    nameservers_used = list(resolver.nameservers)

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    cleaned = hostname.strip().rstrip(".")

    # Test resolution
    overall_status = "NOERROR"

    for rtype in record_types:
        try:
            answers = resolver.resolve(cleaned, rtype)
            overall_status = "NOERROR"
            rtype_answers = []
            for rdata in answers:
                record_entry = {
                    "value": str(rdata),
                    "ttl": answers.rrset.ttl if answers.rrset else None
                }
                rtype_answers.append(record_entry)
            if rtype_answers:
                results[rtype] = rtype_answers
        except dns.resolver.NXDOMAIN:
            overall_status = "NXDOMAIN"
            query_error = "NXDOMAIN: The hostname does not exist in authoritative public DNS."
            break
        except dns.resolver.NoAnswer:
            # Query succeeded at resolver, but no records of this specific type
            continue
        except (dns.resolver.Timeout, dns.resolver.LifetimeTimeout):
            overall_status = "TIMEOUT"
            query_error = f"Lookup timed out after {timeout}s. The upstream DNS resolver did not respond."
            break
        except dns.resolver.NoNameservers:
            overall_status = "SERVFAIL"
            query_error = "SERVFAIL: All nameservers failed to return an answer or were unreachable."
            break
        except Exception as e:
            overall_status = "RESOLVER_ERROR"
            query_error = f"Resolver error ({type(e).__name__}): {str(e)}"
            break

    duration_ms = round((time.time() - start_time) * 1000, 2)
    resolver_status = overall_status

    return {
        "enabled": True,
        "performed": True,
        "query_time_ms": duration_ms,
        "resolver_status": resolver_status,
        "nameservers": nameservers_used[:2],
        "records": results,
        "error": query_error,
        "disclaimer": "Live DNS lookups were executed using the system resolver. Syntactically valid hostnames may not exist in public DNS. Resolution failure does not imply malicious intent."
    }
