package kubernetes.admission

default deny = false

deny {
    input.kind == "Deployment"
    not resourcerequestsavailable
    
}

default cpqrequest = false
cpurequest {
    req := input.spec.template.spec.containers[_].resources.requests.cpu
}

default memoryrequest = false
memoryrequest {
    req := input.spec.template.spec.containers[_].resources.requests.memory
}

default cpulimits = false
cpurequest {
    req := input.spec.template.spec.containers[_].resources.limits.cpu
}

default memorylimits = false
memoryrequest {
    req := input.spec.template.spec.containers[_].resources.limits.memory
}

resourcerequestsavailable {
    cpurequest
    memoryrequest
    cpulimits
    memorylimits
}