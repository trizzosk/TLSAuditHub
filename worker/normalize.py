def normalize_scan(scan_results: list[dict]) -> dict:
    normalized = {
        "tls_versions": set(),
        "cipher_suites": set(),
        "certificate": {},
    }

    for r in scan_results:
        plugin = r["plugin"]
        result = r["result"]

        if plugin == "tlsv1_2_cipher_suites":
            normalized["cipher_suites"].update(
                result.get("accepted_cipher_suites", [])
            )

        if plugin == "certificate_info":
            cert = result.get("certificate_chain", [{}])[0]
            normalized["certificate"] = {
                "subject": cert.get("subject"),
                "issuer": cert.get("issuer"),
                "not_before": cert.get("not_before"),
                "not_after": cert.get("not_after"),
                "san": cert.get("subject_alternative_name"),
            }

        if plugin.startswith("tlsv"):
            if result.get("is_protocol_supported"):
                normalized["tls_versions"].add(plugin)

    return normalized