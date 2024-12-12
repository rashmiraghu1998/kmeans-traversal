"""Oblivious transfer (OT) protocol steps.

Steps for both parties executing an oblivious transfer
protocol to exchange information.
"""
import random

import nacl.encoding
import nacl.hash
import nacl.secret
import nacl.bindings
import oblivious

class ot():
    '''
    Wrapper class for easier merging of modules.
    '''

    #
    # Protocol steps.
    #

    # By default, use the best-effort oblivious
    # primitives.
    primitives = oblivious

    @staticmethod
    def sodium(use=True):
        ot.primitives = oblivious if use else oblivious.native

    @staticmethod
    def key_hash(x):
        # import hashlib
        # return hashlib.blake2s(bytes(x), digest_size=32).digest()
        return nacl.hash.blake2b(bytes(x), encoder=nacl.encoding.RawEncoder)

    @staticmethod
    def key_pair():
        # Private key: x in Zp.
        x = random.choice(range(1000000))

        # Public key: X = g^x.
        point_1 = ot.primitives.bn254.get_base()^x
        g_to_x = x * point_1

        return [x, g_to_x]

    @staticmethod
    def key_pairs(n):
        return map(list, zip(*[ot.key_pair() for _ in range(n)]))

    @staticmethod
    def receiver_send_message(sender_key_public, receiver_key_public, select_bit):
        # The sender's public key is A = g^a.
        g_to_a = sender_key_public

        # Below is the receiver's public key g^b.
        g_to_b = receiver_key_public

        # If receiver's select_bit == 0, B = g^b.
        # If receiver's select_bit == 1, B = A.g^b.
        B_s0 = g_to_b
        B_s1 = g_to_a + g_to_b

        return B_s0 if (select_bit == 0) else B_s1

    @staticmethod
    def sender_send_response(sender_key_secret, sender_key_public, receiver_key_public, m_0, m_1):
        # These are the sender's secret and public keys.
        a = sender_key_secret
        g_to_a = sender_key_public

        # Second argument is receiver's public key B_s, which depends
        # on the receiver's select_bit s and is B_0 = g^b or B_1 = A.g^b.
        B_s = receiver_key_public

        # Build the key for the message for the zero case.
        k_0 = ot.key_hash(a * B_s)

        # Build the key for the message for the one case.
        k_ab = B_s - g_to_a
        k_1 = ot.key_hash(a * k_ab)

        # Encrypt the messages for both cases.
        nonce = bytes([0]*nacl.bindings.crypto_secretbox_NONCEBYTES)

        # Encryption function.
        enc = lambda m, nonce, k: nacl.secret.SecretBox(k).encrypt(m, nonce)[-32:]

        return [enc(m_0, nonce, k_0), enc(m_1, nonce, k_1)]

    @staticmethod
    def receiver_receive_response(sender_public_key, receiver_key_secret, response, select_bit):
        # This is the receiver's secret key b.
        b = receiver_key_secret

        # This is the sender's public key A = g^a.
        g_to_a = sender_public_key

        # Build the decryption key g^(ab).
        k_s = ot.key_hash(b * g_to_a)

        # Decryption function.
        dec = lambda c, k: nacl.secret.SecretBox(k).decrypt(bytes(24) + c)

        # Decrypt the chosen message.
        c_s = response[0 if (select_bit == 0) else 1]
        m_s = dec(c_s, k_s)

        return m_s

    #
    # Convenient operations to handle management of multiple concurrent
    # instances of the protocol.
    #

    @staticmethod
    def receiver_send_messages(sender_keys_public, receiver_keys_public, input):
        """Convenient method for sending a list of messages, one for each input bit."""
        return [
            ot.receiver_send_message(
                sender_keys_public[i], receiver_keys_public[i],
                input[i]
            )
            for i in (range(len(input)))
        ]

    @staticmethod
    def sender_send_responses(sender_keys_secret, sender_keys_public, receiver_keys_public, m_01s):
        """Convenient method for sending a list of responses, one for each input bit."""
        return [
            ot.sender_send_response(
                sender_keys_secret[i], sender_keys_public[i], receiver_keys_public[i],
                m_01s[i][0].bytes(), m_01s[i][1].bytes()
            )
            for i in (range(len(m_01s)))
        ]

    @staticmethod
    def receiver_receive_responses(
            sender_keys_public, receiver_keys_secret, enc_label_pairs, input
        ):
        """Convenient method for receiving a list of responses, one for each input bit."""
        return [
            ot.receiver_receive_response(
                sender_keys_public[i], receiver_keys_secret[i],
                enc_label_pairs[i], input[i]
            )
            for i in (range(len(input)))
        ]
