# Toy policy for the rego_evaluator smoke test: basic arithmetic over an input
# list of numbers. Nothing here is credential-specific -- it just exercises the
# evaluator's job of running an arbitrary Rego policy over an arbitrary input.
#
# Input shape: { "values": [ <number>, ... ] }
#   data.numbers.total -> the sum of the values
#   data.numbers.large -> true when the total exceeds the threshold

package numbers

import rego.v1

threshold := 100

# the sum of all input values
total := sum(input.values)

# a simple threshold check over the computed total
default large := false

large if total > threshold
