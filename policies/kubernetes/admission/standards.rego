package kubernetes.admission

deny[reason] {
    parsedInput := parserequest(input)
    not resourcerequestsavailable(parsedInput.containers)
    reason := "Resource requests are not set."
}

deny[reason] {
    parsedInput := parserequest(input)
    not resourcelimitsavailable(parsedInput.containers)
    reason := "Resource limits are not set."
}

cpurequest(containers) {
    req := containers[_].resources.requests.cpu
}

memoryrequest(containers) {
    req := containers[_].resources.requests.memory
}

cpulimits(containers) {
    req := containers[_].resources.limits.cpu
}

memorylimits(containers) {
    req := containers[_].resources.limits.memory
}

resourcerequestsavailable(containers) {
    cpurequest(containers)
    memoryrequest(containers)
}

resourcelimitsavailable(containers) {
    cpulimits(containers)
    memorylimits(containers)
}

#helper methods

parserequest(input_request) = result {
	input_request.kind != "AdmissionReview"
	kind := input_request.kind
	containers := input_request.spec.template.spec.containers
	result := {
		"kind": kind,
		"containers": containers
	}
}

parserequest(input_request) = result {
	input_request.kind == "AdmissionReview"
	kind := input_request.request.kind.kind
	containers := input_request.request.object.spec.template.spec.containers
	result := {
		"kind": kind,
		"containers": containers
	}
}