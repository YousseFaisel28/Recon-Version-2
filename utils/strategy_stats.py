from collections import Counter, defaultdict

def build_strategy_statistics(strategies):
    stats = {
        "by_source": Counter(),
        "by_confidence": Counter(),
        "by_mitre": Counter(),
        "by_port": Counter(),
        "by_exploit_type": Counter(),
        "attack_chains": defaultdict(int)
    }

    for s in strategies:
        # Source is effectively "Exploit-DB" (Reference) or "Model 5" (Rule-based)
        source = "Exploit-DB" if s.get("exploit_db_reference") else "Model 5 Rules"
        stats["by_source"][source] += 1
        
        # Evidence Status acts as confidence proxy
        status = s.get("evidence_status", "Unknown")
        stats["by_confidence"][status] += 1
        
        stats["by_mitre"][s.get("mitre_technique", "Unknown")] += 1
        
        # Exploit type is now derived from evidence
        if s.get("exploit_db_reference"):
            stats["by_exploit_type"]["Public Exploit"] += 1
        else:
            stats["by_exploit_type"]["Theoretical"] += 1

        # Service string contains ports e.g. "Apache (80, 443)"
        service_str = s.get("service", "")
        if "(" in service_str:
            # Extract basic service name
            svc_name = service_str.split("(")[0].strip()
            stats["by_port"][svc_name] += 1
        else:
            stats["by_port"][service_str] += 1

        chain = " → ".join(s.get("attack_chain") or [])
        if chain:
            stats["attack_chains"][chain] += 1

    # Convert Counters to normal dicts (important for JSON)
    return {k: dict(v) for k, v in stats.items()}
