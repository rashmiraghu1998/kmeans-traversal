import concurrent
from utils import utils
import asyncio
from utils import cryptographicProtocols
async def sspir(pid, queue, P1_points, P2_points, P3_points, P2_kd_tree, P3_kd_tree, i):
    p = utils.Message(queue)

    # Step 1: Party 1 (P1) handles secret sharing and XOR sharing of Q
    if pid == "P1":
        # Secret share the index 'i' between 3 parties: P1, P2, and P3
        i_secret = cryptographicProtocols.secret_share(i, 2, 2)  # This should give us shares of 'i' between P1, P2, and P3
        print("Secret: " + str(i_secret))  # Print the shares of 'i' for debugging

        # Create the bit-array Q of length m
        m = len(P2_kd_tree)  # Assuming P2_kd_tree has length m
        Q = [0] * m
        x1 = i_secret[0][0]  # Index of the secret held by P1
        Q[x1] = 1  # Set Q[x1] = 1, where x1 is the index of the secret

        # XOR share the bit-array Q between P1 and P2
        # UPDATE: Do not do XOR secret share. Instead , just give Q to P2 and P3
        # Q_xor_share = cryptographicProtocols.secret_share(Q, 2, 2)  # P3 and P2 receive XOR shares of Q
        Q_xor_share = [Q,Q]
        print("XOR Q array: " + str(Q_xor_share))

        # Send shares of Q to P2 and P3
        await p.give("XOR_Q_P2", Q_xor_share[0])  # Send P2's share of Q
        await p.give("XOR_Q_P3", Q_xor_share[1])  # Send P3's share of Q

        # Send the secret share to P2 and P3 (for index i)
        await p.give("i_P2", i_secret[0][1])  # P2 receives its share of the index
        await p.give("i_P3", i_secret[0][1])  # P3 receives its share of the index
        #
        # # Receive the results from P2 and P3 (v_P2 and v_P3)
        # v_P2 = await p.get("v_P2")
        # v_P3 = await p.get("v_P3")
        #
        # print("P2's result: " + str(v_P2))
        # print("P3's result: " + str(v_P3))
        #
        # # Combine the results from P2 and P3 (add them together)
        # v = [v_P3[j] + v_P2[j] for j in range(len(v_P3))]
        # print("Combined v: " + str(v))

        # # Return the final result based on the secret share and index i
        # result = v[(i_secret[0][1] + i) % 2]  # Select the correct result based on the index 'i' and secret share
        # print("Final result: " + str(result))
        # return result

    # Step 2: Party 2 (P2) handles permuting Q and computing v_P2
    if pid == "P2":
        # Receive XOR-shared Q and the secret share for index i
        Q = await p.get("XOR_Q_P2")
        i = await p.get("i_P2")  # This is the secret share of 'i' for P2

        # Permute the array Q using the value of i (secret share)
        W = [Q[(i + j) % len(Q)] for j in range(len(Q))]  # Permutation based on 'i'
        print("Received Q_P2: " + str(Q))
        print("Permuted W_P2: " + str(W))

        # Compute the values v_P2 based on the KD-tree values and W
        v_P2 = [P2_kd_tree[j] * W[j] for j in range(len(P2_kd_tree))]  # Multiply the KD-tree values with W
        print("Computed V_P2: " + str(v_P2))

        # Send the result back to P1. Do not!! We will use P2 as a participant.
        # await p.give("v_P2", v_P2)

    # Step 3: Party 3 (P3) handles permuting Q and computing v_P3
    if pid == "P3":
        # Receive XOR-shared Q and the secret share for index i
        Q = await p.get("XOR_Q_P3")
        i = await p.get("i_P3")  # This is the secret share of 'i' for P3

        # Permute the array Q using the value of i (secret share)
        W = [Q[(i + j) % len(Q)] for j in range(len(Q))]  # Permutation based on 'i'
        print("Received Q_P3: " + str(Q))
        print("Permuted W_P3: " + str(W))

        # Compute the values v_P3 based on the KD-tree values and W
        v_P3 = [P3_kd_tree[j] * W[j] for j in range(len(P3_kd_tree))]  # Multiply the KD-tree values with W
        print("Computed V_P3: " + str(v_P3))

        # Send the result back to P1 : Do not!! We will use P3 as a participant.
        # await p.give("v_P3", v_P3)

async def main():
    futures = []
    P1_points = [1,1,1]
    # centroids: 4, 5, 6, 8
    # kd-tree: [5.25, 4.5, 7, 4, 5,6,8]
    P2_kd_tree = [5, 4, 4, 2, 3, 3, 4]
    P2_points = [1,2,3]
    P3_kd_tree = [0.25, 0.5, 3, 2, 2, 3, 4]
    P3_points = [0,1,2]
    # first index i is 0 and known to everyone.
    i=0
    queue = asyncio.Queue()
    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor() as executor:
        """
        Three parties - Non colluding.
        Each party has secret shares of the points.
        P2 and P3 have secret shares of the kd-tree.
        """
        for parties in ["P1", "P2", "P3"]:
            futures.append(await loop.run_in_executor(executor, sspir, parties, queue,P1_points, P2_points, P3_points, P2_kd_tree, P3_kd_tree, i))
        [await f for f in asyncio.as_completed(futures)]


if __name__ == "__main__":
    asyncio.run(main())