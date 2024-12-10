import concurrent
import copy

from utils import utils
import asyncio
from utils import cryptographicProtocols

async def sspir(pid, queue, P0_points, P1_points, P2_points, P1_kd_tree, P2_kd_tree, index):

    p = utils.Message(queue)
    # Step 1: Party 0 (P0) handles secret sharing and XOR sharing of Q
    if pid == "P0":
        # Secret share the index 'i' between 3 parties: P0, P1, and P2
        i_secret = cryptographicProtocols.secret_share(index, 2)  # This should give us shares of 'i' between P0, P1, and P2
        print("Secret: " + str(i_secret))  # Print the shares of 'i' for debugging

        await p.give("i_P1", int(i_secret[0][1],2))  # P1 receives its share of the index
        await p.give("i_P2", int(i_secret[0][1],2))  # P2 receives its share of the index

        # Create the bit-array Q of length m
        m = len(P2_kd_tree)  # Assuming P2_kd_tree has length m
        Q = [0] * m

        Q[int(i_secret[0][0],2)] = 1  # Set Q[x1] = 1

        # XOR share the bit-array Q between P1 and P2
        Q_xor_share = cryptographicProtocols.secret_share(Q, 2)  # P2 and P1 receive XOR shares of Q

        # Q_xor_share = [Q, Q]
        print("XOR Q array: " + str(Q_xor_share))

        # Send shares of Q to P1 and P2
        await p.give("XOR_Q_P1", Q_xor_share[:][0])  # Send P1's share of Q
        await p.give("XOR_Q_P2", Q_xor_share[:][1])  # Send P2's share of Q

    # Step 2: Party 1 (P1) handles permuting Q and computing v_P1
    if pid == "P1":
        # Create a copy of kd_tree
        bin_P1_kd_tree = []
        for i in P1_kd_tree:
            bin_P1_kd_tree.append(bin(i)[2:])

        # Receive XOR-shared Q and the secret share for index i
        Q = await p.get("XOR_Q_P1")
        index = await p.get("i_P1")  # This is the secret share of 'i' for P1

        # Permute the array Q using the value of i (secret share)
        W = [Q[(index + j) % len(Q)] for j in range(len(Q))]  # Permutation based on 'i'
        print("Received Q_P1: " + str(Q))
        print("Permuted W_P1: " + str(W))

        # Compute the values v_P2 based on the KD-tree values and W
        v_P1 = []
        v_P1.append([int(bin_P1_kd_tree[j] * W[j],2) for j in range(len(bin_P1_kd_tree))])  # Multiply the KD-tree values with W
        print("Computed V_P1: " + str(v_P1))

    # Step 3: Party 2 (P2) handles permuting Q and computing v_P3
    if pid == "P2":
        # Create a copy of kd_tree
        bin_P2_kd_tree = []
        for i in P2_kd_tree:
            bin_P2_kd_tree.append(bin(i)[2:])

        # Receive XOR-shared Q and the secret share for index i
        Q = await p.get("XOR_Q_P2")
        index = await p.get("i_P2")  # This is the secret share of 'i' for P2
        # Permute the array Q using the value of i (secret share)
        W = [Q[(index + j) % len(Q)] for j in range(len(Q))]  # Permutation based on 'i'
        print("Received Q_P2: " + str(Q))
        print("Permuted W_P2: " + str(W))

        # Compute the values v_P2 based on the KD-tree values and W
        v_P2 = []
        # v_P2 is wrong. Need to xor.
        v_P2.append([int(int(bin_P2_kd_tree[j])[i] * W[j],2) for j in range(len(bin_P2_kd_tree))])  # Multiply the KD-tree values with W
        print("Computed V_P2: " + str(v_P2))

async def traversal(pid, queue, P0_points, P1_points, P2_points, P1_kd_tree, P2_kd_tree, index):
    p = utils.Message(queue)

    # Convert P1 and P2 points into binary.
    bin_P1_points = []
    for i in P1_points:
        bin_P1_points.append(bin(i)[2:])
    bin_P2_points = []
    for i in P2_points:
        bin_P2_points.append(bin(i)[2:])

    # Step 1: Party 0 secret shares the datapoints with P1 and P2
    if pid == "P0":
        secret_datapoints = cryptographicProtocols.secret_share(P0_points, 2)
        print("Secret"+str(secret_datapoints))
        for i in range(len(P0_points)):
            bin_P1_points[i]= bin(int(bin_P1_points[i], 2) + int(secret_datapoints[0][i],2))[2:]
            bin_P2_points[i]= bin(int(bin_P2_points[i], 2) + int(secret_datapoints[1][i],2))[2:]

    # Step 2: Party 0 , Party 1 and Party 2 perform SSPIR to get kd_tree[i]
    await sspir(pid, queue, P0_points, bin_P1_points, bin_P2_points, P1_kd_tree, P2_kd_tree, index)

async def main():
    futures = []
    P0_points = [4,1,1]
    # centroids: 4, 5, 6, 8
    # kd-tree: [5.25, 4.5, 7, 4, 5,6,8]
    P1_kd_tree = [5, 4, 4, 2, 3, 3, 4]
    P1_points = [1,2,3]
    P2_kd_tree = [1, 1, 3, 2, 2, 3, 4]
    P2_points = [0,1,2]
    # first index i is 0 and known to everyone.
    i=3
    queue = asyncio.Queue()
    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor() as executor:
        """
        Three parties - Non colluding.
        Each party has secret shares of the points.
        P1 and P2 have secret shares of the kd-tree.
        """
        for parties in ["P0", "P1", "P2"]:
            futures.append(await loop.run_in_executor(executor, traversal, parties, queue, P0_points, P1_points, P2_points, P1_kd_tree, P2_kd_tree, 3))
        [await f for f in asyncio.as_completed(futures)]


if __name__ == "__main__":
    asyncio.run(main())