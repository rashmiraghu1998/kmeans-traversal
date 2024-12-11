import concurrent
import copy

import oblivious
from oblivious.ristretto import point, scalar
from bcl import symmetric, secret
from hashlib import sha512
from utils import utils
import asyncio
from utils import cryptographicProtocols


async def OT_output(pid, p, x_0, x_1, selector):
    point_1 = oblivious.ristretto.point.hash('abc'.encode())
    if(pid == "P1"):
        encoded_x0 = x_0.encode()
        encoded_x1 = x_1.encode()
        a = scalar()
        # print(a)
        A = a * point_1
        # print(A)
        await p.give("A", A)
        B = await p.get("B")

        key0 = a * B
        key1 = a * (B - A)

        key0_bytes = sha512(key0.canonical().to_base64().encode()).digest()[:32]
        key1_bytes = sha512(key1.canonical().to_base64().encode()).digest()[:32]
        ct0 = symmetric.encrypt(secret(key0_bytes), encoded_x0)
        ct1 = symmetric.encrypt(secret(key1_bytes), encoded_x1)
        await p.give("ct0", ct0)
        await p.give("ct1", ct1)

    if(pid == "P0"):
        value = 0
        for i in selector:
            value = cryptographicProtocols.xor(value, i)
        b = scalar.from_int(0)
        # print(b)
        A = await p.get("A")
        if (value == 0):
            B = (b * A)
        else:
            B = A + (b * A)
        await p.give("B", B)
        keyr = b * A

        keyr_bytes = sha512(keyr.canonical().to_base64().encode()).digest()[:32]
        # print(keyr, keyr.canonical().to_base64().encode(), keyr_bytes)
        ct0 = await p.get("ct0")
        ct1 = await p.get("ct1")

        try:
            d0 = symmetric.decrypt(secret(keyr_bytes), ct0)
            return [ct0,d0]
            print(d0)
        except:
            d1 = symmetric.decrypt(secret(keyr_bytes), ct1)
            return [ct1,d1]
            print(d1)

    if(pid == "P2"):
        pass



async def OT_input(pid, p, x_0, x_1, value):
    point_1 = oblivious.ristretto.point.hash('abc'.encode())

    if(pid == "P1"):
        encoded_x0 = x_0.encode()
        encoded_x1 = x_1.encode()
        a = scalar()
        # print(a)
        A = a * point_1
        # print(A)
        await p.give("A", A)
        B = await p.get("B")

        key0 = a * B
        key1 = a * (B - A)

        key0_bytes = sha512(key0.canonical().to_base64().encode()).digest()[:32]
        key1_bytes = sha512(key1.canonical().to_base64().encode()).digest()[:32]
        ct0 = symmetric.encrypt(secret(key0_bytes), encoded_x0)
        ct1 = symmetric.encrypt(secret(key1_bytes), encoded_x1)
        await p.give("ct0", ct0)
        await p.give("ct1", ct1)

    if(pid == "P2"):
        b = scalar.from_int(0)
        # print(b)
        A = await p.get("A")
        if(value==0):
            B = (b * A)
        else:
            B = A + (b * A)
        await p.give("B", B)
        keyr = b * A

        keyr_bytes = sha512(keyr.canonical().to_base64().encode()).digest()[:32]
        # print(keyr, keyr.canonical().to_base64().encode(), keyr_bytes)
        ct0 = await p.get("ct0")
        ct1 = await p.get("ct1")

        try:
            d0 = symmetric.decrypt(secret(keyr_bytes), ct0)
            print(d0)
        except:
            d1 = symmetric.decrypt(secret(keyr_bytes), ct1)
            print(d1)

        B = (b * A)
        await p.give("B", B)
        keyr = b * A

        keyr_bytes = sha512(keyr.canonical().to_base64().encode()).digest()[:32]
        # print(keyr, keyr.canonical().to_base64().encode(), keyr_bytes)
        ct0 = await p.get("ct0")
        ct1 = await p.get("ct1")

        try:
            d0 = symmetric.decrypt(secret(keyr_bytes), ct0)
            return ct0
            print(d0)
        except:
            d1 = symmetric.decrypt(secret(keyr_bytes), ct1)
            return ct1
            print(d1)





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

        Q[int(i_secret[0][0],2)%len(Q)] = 1  # Set Q[x1] = 1

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
        # v_P2 is wrong. Need to xor.
        # Multiply the KD-tree values with W
        for j in range(len(bin_P1_kd_tree)):
            k = 0
            for i in bin_P1_kd_tree:
                k = k^((int(i) * int(W[j])))
            v_P1.append(k)
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
        # Multiply the KD-tree values with W
        print(bin_P2_kd_tree)
        for j in range(len(bin_P2_kd_tree)):
            k=0
            for i in bin_P2_kd_tree:
                k=k^((int(i)*int(W[j])))
            v_P2.append(k)

        print("Computed V_P2: " + str(v_P2))

async def traversal(pid, queue, P0_points, P1_points, P2_points, P1_kd_tree, P2_kd_tree, index):
    p = utils.Message(queue)
    print(pid)
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
    # Step 3: Perform OT between P2 and P1 to get all cipher texts.
    cipherTestForZero = await OT_input(pid, p, "0", "1", 0)
    print(cipherTestForZero)
    cipherTestForOne = await OT_input(pid, p, "0", "1", 1)
    print(cipherTestForOne)

    if pid == "P0":
        
        # Step 4: Perform OT between P1 and P0 to get encrypted output to get the value of b.
        cipherForOutput,output = await OT_output(pid, p, "01010", "10101", "1010101")
        # Step 5: Update new index.
        if output == 0:
            index = index+1
        else:
            index = index+2
        # Step 6: Index vector
        if index > len(P2_kd_tree)//2:
            cp = [0]*(len(P2_kd_tree))
            cp[index] = 1
            cp_secret = cryptographicProtocols.secret_share(cp, 2)
            await p.give("cp_1", cp_secret[0])
            await p.give("cp_2", cp_secret[1])

    # Step 7: Use the index vectors for updates later.
    if pid == "P1":
        cp = await p.get("cp_1")
    if pid == "P2":
        cp = await p.get("cp_2")









    
    
    
    











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
    i=4
    queue = asyncio.Queue()
    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor() as executor:
        """
        Three parties - Non colluding.
        Each party has secret shares of the points.
        P1 and P2 have secret shares of the kd-tree.
        """
        for parties in ["P0", "P1", "P2"]:
            futures.append(await loop.run_in_executor(executor, traversal, parties, queue, P0_points, P1_points, P2_points, P1_kd_tree, P2_kd_tree, 4))
        [await f for f in asyncio.as_completed(futures)]


if __name__ == "__main__":
    asyncio.run(main())