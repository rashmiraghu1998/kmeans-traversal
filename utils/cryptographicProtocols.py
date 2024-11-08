import random
import numpy
def secret_share(items, parties, q):
    elements=[]
    if type(items)==int:
        elements.extend([items])
    else:
        elements.extend(items)
    print(elements)
    secretShares=[0]*len(elements)

    for i in range(len(elements)):
        shareFori=[]
        for j in range(parties):
            if j is not parties-1:
                value = random.choice(range(q))
                shareFori.append(value)
            else:
                shareFori.append(abs(elements[i]-sum(shareFori)%q))
        secretShares[i]=shareFori
    if len(elements)==1:
        return secretShares
    else:
        return list(zip(*secretShares))







