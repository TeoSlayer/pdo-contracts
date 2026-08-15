# Toy string policy for the rego_evaluator smoke test. Nothing credential-specific
# -- it just builds a greeting from the input name.
#
# Input shape: { "name": <string> }
#   data.greeting.message -> "hello, <name>!"

package greeting

import rego.v1

message := sprintf("hello, %s!", [input.name])
