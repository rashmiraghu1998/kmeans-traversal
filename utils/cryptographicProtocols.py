import random
import numpy
def secret_share(items, parties):
    elements=[]
    if type(items)==int:
        elements.extend([items])
    else:
        elements.extend(items)
    print("Elements"+str(elements))
    secretShares=[]

    for i in range(len(elements)):
        binary = bin(elements[i])
        # print(binary)
        shares = []
        for j in range(parties-1):
            shares.append("".join([str(random.choice([0,1])) for k in range(len(binary)-2)]))
        # print(shares)
        m = list(binary[2:])
        for i in range(2, len(binary)):
            value = int(binary[i])
            for j in range(parties-1):
                value+= int(shares[j][i-2])
            m[i-2]=str(value%2)
        shares.append(str("".join(m)))
        secretShares.append(shares)

    if(len(secretShares)==1):
        return secretShares
    return list(zip(*secretShares))


def xor(a,b):
    print("".join(['0']*(len(str(a))-len(str(b)))))
    a_new = a
    b_new = b
    if(len(str(a)) > len(str(b))):
        a_new = "".join(['0']*(len(str(a))-len(str(b))))+""+"".join(list(a))
        b_new = b
    elif(len(str(a)) < len(str(b))):
        a_new = a
        b_new = "".join(['0']*(len(str(b))-len(str(a))))+""+"".join(list(b))

    return "".join([str(int(str(a_new)[i])^int(str(b_new)[i])) for i in range((len(str(a_new))))])






