package athena.system

import rego.v1

default allow := false

allow if {
    input.operation == "health"
}
