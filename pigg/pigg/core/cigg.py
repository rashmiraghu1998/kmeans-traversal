"""Wrapper for CIGG dynamic library.

Wrappers and bindings for CIGG library functions
implementing garbled circuit and OT protocol steps.
"""

import platform
import ctypes
import parts
import canaries

class cigg():
    '''
    Wrapper class for easier merging of modules.
    '''

    lib = None

    # Names of circuits already embedded in a CIGG library file.
    embedded = [
        "aes-128-ecb-encrypt", "aes-128-ecb-decrypt",
        "sha-256-for-lteq-440-bits", "sha-256-for-lteq-952-bits"
    ]

    @staticmethod
    def server_encrypt_to_self(key, message):
        '''Server-side state communication symmetric encryption.'''
        crypto_secretbox_MACBYTES = 16
        ciphertext = ctypes.create_string_buffer(len(message)+crypto_secretbox_MACBYTES)
        cigg.lib.server_encrypt_to_self(
            ciphertext, 
            ctypes.create_string_buffer(key), 
            ctypes.create_string_buffer(bytes(message)), 
            len(message)
        )
        return bytes(ciphertext.raw)

    @staticmethod
    def server_decrypt_from_self(key, ciphertext):
        '''Server-side state communication symmetric encryption.'''
        crypto_secretbox_MACBYTES = 16
        message = ctypes.create_string_buffer(len(ciphertext)-crypto_secretbox_MACBYTES)
        cigg.lib.server_decrypt_from_self(
            message, 
            ctypes.create_string_buffer(key), 
            ctypes.create_string_buffer(bytes(ciphertext)), 
            len(ciphertext)
        )
        return bytes(message.raw)

    @staticmethod
    def server_get_gates_wires(index, input_one, input_two_len):
        '''Garbled circuit protocol wire labeling and gate garbling steps.'''
        # Get lengths of data items from CIGG.
        lengths = ctypes.create_string_buffer(5*4)
        cigg.lib.server_get_gates_wires_lengths(lengths, index)
        lengths = [int.from_bytes(p, 'big') for p in parts.parts(lengths.raw, length=4)]

        # Allotment buffer lengths should be determined by inputs and not
        # circuit signature (if inputs are split differently).
        lengths[1] = (1 + 4 + len(input_one)*(2+1*16))
        lengths[2] = (1 + 4 + input_two_len*(2+2*16))

        # Obtain the wire-to-label(s) maps.
        wiotl = ctypes.create_string_buffer(lengths[1])
        wittl = ctypes.create_string_buffer(lengths[2])
        wotl = ctypes.create_string_buffer(lengths[3])
        gg = ctypes.create_string_buffer(lengths[4])
        cigg.lib.server_get_gates_wires(
            wiotl, wittl, wotl, gg, 
            index, 
            ctypes.create_string_buffer(bytes(input_one)), 
            len(input_one)
        )
        return (wiotl, wittl, wotl, gg)

    @staticmethod
    def client_evaluate(length_output, index, wire_in_to_label, gates_garbled):
        '''Garbled circuit protocol evaluation step.'''
        wtls_out = ctypes.create_string_buffer(length_output)
        cigg.lib.client_evaluate(
            wtls_out, 
            index, 
            ctypes.create_string_buffer(wire_in_to_label),
            ctypes.create_string_buffer(gates_garbled)
        )
        return bytes(wtls_out)

    @staticmethod
    def server_ot_key_pairs(quantity):
        '''Server public-private key pairs for OT protocol.'''
        secret_keys = ctypes.create_string_buffer(32*quantity)
        public_keys = ctypes.create_string_buffer(32*quantity)
        cigg.lib.server_ot_key_pairs(secret_keys, public_keys, quantity)
        return (
            [bytes(p) for p in parts.parts(secret_keys, length=32)],
            [bytes(p) for p in parts.parts(public_keys, length=32)]
        )

    @staticmethod
    def client_ot_key_pairs(quantity):
        '''Client public-private key pairs for OT protocol.'''
        secret_keys = ctypes.create_string_buffer(32*quantity)
        public_keys = ctypes.create_string_buffer(32*quantity)
        cigg.lib.client_ot_key_pairs(secret_keys, public_keys, quantity)
        return (
            [bytes(p) for p in parts.parts(secret_keys, length=32)],
            [bytes(p) for p in parts.parts(public_keys, length=32)]
        )

    @staticmethod
    def client_ot_receiver_send_messages(
            sender_keys_public, receiver_keys_public,
            bits
        ):
        '''Initial client OT protocol step.'''
        key_per_bit = ctypes.create_string_buffer(32*len(bits))
        cigg.lib.client_ot_receiver_send_messages(
            key_per_bit, 
            ctypes.create_string_buffer(bytes(sender_keys_public)), 
            ctypes.create_string_buffer(bytes(receiver_keys_public)), 
            ctypes.create_string_buffer(bytes(bits)), 
            len(bits)
        )
        return [bytes(p) for p in parts.parts(key_per_bit, length=32)]

    @staticmethod
    def server_ot_sender_send_responses(
            sender_keys_secret, sender_keys_public, receiver_keys_public,
            messages, length
        ):
        '''Server OT protocol step.'''
        pair_per_bit = ctypes.create_string_buffer(32*2*length)
        cigg.lib.server_ot_sender_send_responses(
            pair_per_bit, 
            ctypes.create_string_buffer(bytes(sender_keys_secret)), 
            ctypes.create_string_buffer(bytes(sender_keys_public)), 
            ctypes.create_string_buffer(bytes(receiver_keys_public)), 
            ctypes.create_string_buffer(bytes(messages)), 
            length
        )
        return [
            [bytes(pair[:32]), bytes(pair[32:])]
            for pair in parts.parts(pair_per_bit, length=(32*2))
        ]

    @staticmethod
    def client_ot_receiver_receive_responses(
            sender_keys_public, receiver_keys_secret,
            messages, bits, length
        ):
        '''Final client OT protocol step.'''
        label_per_bit = ctypes.create_string_buffer(16*length)
        cigg.lib.client_ot_receiver_receive_responses(
            label_per_bit, 
            ctypes.create_string_buffer(bytes(sender_keys_public)), 
            ctypes.create_string_buffer(bytes(receiver_keys_secret)), 
            ctypes.create_string_buffer(bytes(messages)), 
            ctypes.create_string_buffer(bytes(bits)), 
            length
        )
        return [bytes(p) for p in parts.parts(label_per_bit, length=16)]

# Determine whether there is a CIGG library file in the environment.
cigg.lib = canaries.load({
    'Linux': ['./cigg.linux.64.so', './cigg.linux.32.so'],
    'Darwin': ['./cigg.macos.64.so', './cigg.macos.32.so'],
    'Windows': ['./cigg.win.64.dll', './cigg.win.32.dll']
})
