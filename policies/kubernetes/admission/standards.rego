package kubernetes.admission

#deny if resource requests are not set for all containers
deny[reason] {
    parsedInput := parserequest(input)
    not resourcerequestsavailable(parsedInput.containers)
    reason := "Resource requests are not set."
}

#deny if resource limits are not set for all containers
deny[reason] {
    parsedInput := parserequest(input)
    not resourcelimitsavailable(parsedInput.containers)
    reason := "Resource limits are not set."
}

#returns true if cpu requests are set for all containers
cpurequest(containers) {
    req := containers[_].resources.requests.cpu
}

#returns true if memory requests are set for all containers
memoryrequest(containers) {
    req := containers[_].resources.requests.memory
}

#returns true if cpu limits are set for all containers
cpulimits(containers) {
    req := containers[_].resources.limits.cpu
}

#returns true if memory limits are set for all containers
memorylimits(containers) {
    req := containers[_].resources.limits.memory
}

#returns true if both cpurequest and memoryrequest return true
resourcerequestsavailable(containers) {
    cpurequest(containers)
    memoryrequest(containers)
}

#returns true if both cpulimits and memorylimits return true
resourcelimitsavailable(containers) {
    cpulimits(containers)
    memorylimits(containers)
}

#helper methods
#to parse the necessary parameters from different input requests.
#This is necessary since the AdmissionReview request structure differs
#from the deployment manifest.
#The two functions below have same name and same output (result) variable.
#The value of 'result' is the value for which all the encompassing statements are true

parserequest(input_request) = result {
	input_request.kind != "AdmissionReview"
	kind := input_request.kind
	containers := input_request.spec.template.spec.containers
    metadata := input_request.metadata
	result := {
		"kind": kind,
		"containers": containers,
        "metadata": metadata
	}
}

parserequest(input_request) = result {
	input_request.kind == "AdmissionReview"
	kind := input_request.request.kind.kind
	containers := input_request.request.object.spec.template.spec.containers
    metadata := input_request.request.object.metadata
	result := {
		"kind": kind,
		"containers": containers,
        "metadata": metadata
	}
}

# deny if any container is running in privileged mode

deny[reason] {
    parsedInput := parserequest(input)
    container := parsedInput.containers[_].securityContext.privileged
    reason := "Containers must not be run in privileged mode"
}

