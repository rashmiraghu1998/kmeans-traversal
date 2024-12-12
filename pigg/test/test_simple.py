import sys
sys.path.append("..")  # To ensure import statements below work.
from pigg.core.client import *
from test import input_random, protocol_client_server

circuit_name = sys.argv[1]
print(circuit_name)

inputs = input_random(circuits.load(circuit_name))
print(inputs)

output = protocol_client_server(circuit_name, inputs, server_cigg=False, client_cigg=False)
print(output)
