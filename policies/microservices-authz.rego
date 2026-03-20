package microservices.authz

default allow = false

allowed_calls := {
    "service-orders": {
        "service-auth":    ["GET", "POST"],
        "service-payment": ["GET", "POST"],
    },
    "service-payment": {
        "service-notification": ["POST"],
        "service-auth":         ["GET"],
    },
    "service-auth": {
        "service-notification": ["POST"],
    },
}

allow {
    allowed_calls[input.source_service][input.destination_service][_] == input.http_method
}

violations[msg] {
    not allow
    msg = sprintf(
        "VIOLATION: %v -> %v via %v non autorise",
        [input.source_service, input.destination_service, input.http_method]
    )
}

compliance_score = 1.0 {
    count(violations) == 0
}

compliance_score = score {
    count(violations) > 0
    score = 1.0 - (count(violations) * 0.1)
    score > 0
}

compliance_score = 0.0 {
    count(violations) > 0
    1.0 - (count(violations) * 0.1) <= 0
}