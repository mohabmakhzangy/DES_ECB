def is_ascii(s):
    return all(ord(c) < 128 for c in s)


def str2ascii(string):
    res = ""
    for i in range(len(string)):
        hex_val = hex(ord(string[i]))
        res += hex_val[2:]
    return res.upper()


def ascii2str(ascii):
    res = ""
    for i in range(0, len(ascii), 2):
        twoChars = ascii[i] + ascii[i + 1]
        dec = int(twoChars, 16)
        print("chars:", twoChars, "dec:", dec)
        res += chr(dec)
    return res


def ascii2binary(ascii):
    dct = {'0': "0000",
           '1': "0001",
           '2': "0010",
           '3': "0011",
           '4': "0100",
           '5': "0101",
           '6': "0110",
           '7': "0111",
           '8': "1000",
           '9': "1001",
           'A': "1010",
           'B': "1011",
           'C': "1100",
           'D': "1101",
           'E': "1110",
           'F': "1111"}
    binary = ""
    for i in range(len(ascii)):
        binary += dct[ascii[i]]
    return binary


def binary2ascii(bin):
    dct = {"0000": '0',
           "0001": '1',
           "0010": '2',
           "0011": '3',
           "0100": '4',
           "0101": '5',
           "0110": '6',
           "0111": '7',
           "1000": '8',
           "1001": '9',
           "1010": 'A',
           "1011": 'B',
           "1100": 'C',
           "1101": 'D',
           "1110": 'E',
           "1111": 'F'}
    asc = ""
    split = divideBinary(bin, 4)
    for i in range(len(split)):
        asc += dct[split[i]]
    return asc


def decToBinary4Bits(num):
    dct = {0: "0000",
           1: "0001",
           2: "0010",
           3: "0011",
           4: "0100",
           5: "0101",
           6: "0110",
           7: "0111",
           8: "1000",
           9: "1001",
           10: "1010",
           11: "1011",
           12: "1100",
           13: "1101",
           14: "1110",
           15: "1111"}

    return dct[num]


def decToHex(num):
    dct = {0: "00",
           1: "01",
           2: "02",
           3: "03",
           4: "04",
           5: "05",
           6: "06",
           7: "07",
           8: "08",
           9: "09",
           10: "0A",
           11: "0B",
           12: "0C",
           13: "0D",
           14: "0E",
           15: "0F"}

    return dct[num]


def printWithSpace(bin):
    for i in range(len(bin)):
        if (i + 1) % 4 == 0:
            print(bin[i], end=' ')
        else:
            print(bin[i], end='')
    print()


def printFor56(bin):
    for i in range(len(bin)):
        if (i + 1) % 7 == 0:
            print(bin[i], end=' ')
        else:
            print(bin[i], end='')
    print()


def printFor48(bin):
    for i in range(len(bin)):
        if (i + 1) % 6 == 0:
            print(bin[i], end=' ')
        else:
            print(bin[i], end='')
    print()


def printFor64(bin):
    for i in range(len(bin)):
        if (i + 1) % 8 == 0:
            print(bin[i], end=' ')
        else:
            print(bin[i], end='')
    print()


def shift_left(bin, shiftAmount):
    s = ""
    for i in range(shiftAmount):
        for j in range(1, len(bin)):
            s = s + bin[j]
        s = s + bin[0]
        bin = s
        s = ""
    return bin


def xor(s1, s2):
    res = ""
    for i in range(len(s1)):
        if s1[i] == s2[i]:
            res += '0'
        else:
            res += '1'
    return res


# divides binary n by n ex: if bin = 11001101 and n is 2 res: [11, 00, 11, 01]
def divideBinary(bin, n):
    list = []
    str = ""
    for i in range(len(bin)):
        if (i + 1) % n == 0:
            str += bin[i]
            list.append(str)
            str = ""
        else:
            str += bin[i]
    return list


def padBin(bin, n):
    k = n - len(bin)
    s = ""
    for i in range(k):
        s += '0'
    bin = s + bin
    return bin


# initial permutation values
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# key permute table (to shrink 64 bit key into 56 bits)
PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

# key permute table (to shrink 56 bit key into 48 bits)
PC2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

# number of shifts on each iteration
leftShiftNumbers = [1, 1, 2, 2,
                    2, 2, 2, 2,
                    1, 2, 2, 2,
                    2, 2, 2, 1]

# e-bit selection table
eBitSel = [32, 1, 2, 3, 4, 5, 4, 5,
           6, 7, 8, 9, 8, 9, 10, 11,
           12, 13, 12, 13, 14, 15, 16, 17,
           16, 17, 18, 19, 20, 21, 20, 21,
           22, 23, 24, 25, 24, 25, 26, 27,
           28, 29, 28, 29, 30, 31, 32, 1]

# s tables
sTables = [

    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]

]

# permutation table in FIPS46-3
Permutation = [16, 7, 20, 21,
               29, 12, 28, 17,
               1, 15, 23, 26,
               5, 18, 31, 10,
               2, 8, 24, 14,
               32, 27, 3, 9,
               19, 13, 30, 6,
               22, 11, 4, 25]

# IP-1 (reverse inital permutation)
IPreverse = [40, 8, 48, 16, 56, 24, 64, 32,
             39, 7, 47, 15, 55, 23, 63, 31,
             38, 6, 46, 14, 54, 22, 62, 30,
             37, 5, 45, 13, 53, 21, 61, 29,
             36, 4, 44, 12, 52, 20, 60, 28,
             35, 3, 43, 11, 51, 19, 59, 27,
             34, 2, 42, 10, 50, 18, 58, 26,
             33, 1, 41, 9, 49, 17, 57, 25]

plainText = ""
initialKey = ""
nrRounds = 1  # nr of rounds for ECB mode

while True:
    plainText = input("Enter the plain text: ")
    if is_ascii(plainText):
        break
    print("You are not allowed to enter an input containing non-ASCII characters.\n")

while True:
    initialKey = input("\nEnter the inital key (8 characters): ")
    if len(initialKey) != 8:
        print("Wrong size of key. Enter 8 characters only.")
        continue
    if is_ascii(plainText):
        break
    print("You are allowed to enter an input containing non-ASCII characters.")

# arrange plaintexts since its size may change
# converting plain text into ascii code, then binary representation
asciiPT = str2ascii(plainText)  # i.e. = "0123456789ABCDEF"
print("\n\nASCII code of input: ", asciiPT)
lenAsc = len(asciiPT)

# in DES input should be 16 blocks of 4 bits (64 bits in total)
# split the plaintext for ECB mode
nrECB = (lenAsc // 16)
if lenAsc % 16 != 0: nrECB += 1

n = 16
listPT = [asciiPT[i:i + n] for i in range(0, len(asciiPT), n)]
listCT = []

for ECBr in range(nrECB):
    print("\nECB round ", ECBr, "starts...")

    lenAsc = len(listPT[ECBr])
    if lenAsc < 16:
        print("\nPT will be padded since it is less than 64 bits.")
        # calculate how many bits required for padding
        padReq = (16 - lenAsc) // 2  # required number of bytes for padding
        # RFC 5662: The value of each added byte is the number of bytes that are added
        # Ex: We have missing 3 bytes we should add 03 03 03 to the end of input
        hexReq = decToHex(padReq)
        myPT = listPT[ECBr]
        for iteration in range(padReq):
            myPT += hexReq
        listPT[ECBr] = myPT
        print("\nASCII code after padding: ", listPT[ECBr])

    binaryPT = ascii2binary(listPT[ECBr])
    print("\n\nBinary representation of plain text:")
    printWithSpace(binaryPT)

    # converting initial key into ascii code, then binary representation
    asciiIK = str2ascii(initialKey)  # i.e. = "133457799BBCDFF1"
    # print(asciiIK)
    binaryIK = ascii2binary(asciiIK)
    print("\nBinary representation of initial key:")
    printWithSpace(binaryIK)

    # permute binary plain text with initial permutation
    permuted = ""

    for i in range(64):
        index = IP[i] - 1
        permuted += binaryPT[index]
    print("\nAfter Initial Permutation:")
    printWithSpace(permuted)

    # separating to left and right
    left = permuted[0:32]
    right = permuted[32:]
    print("\nAfter splitting into two pieces:")
    print("Left part:  ", end="")
    printWithSpace(left)
    print("Right part: ", end="")
    printWithSpace(right)

    # permuting key with PC-1 table
    permutedKey = ""
    for i in range(56):
        index = PC1[i] - 1
        permutedKey += binaryIK[index]

    print("\nAfter PC-1 permutation the key is: ")
    printFor56(permutedKey)

    # split this key into left and right halves
    leftKey = permutedKey[0:28]
    rightKey = permutedKey[28:]
    print("\nAfter splitting the key into two pieces:")
    print("Left key part:  ", end="")
    printFor56(leftKey)
    print("Right key part: ", end="")
    printFor56(rightKey)

    keyListLeft = []
    keyListRight = []

    shiftedKeyLeft = leftKey
    shiftedKeyRight = rightKey

    # creating subkeys by using left shift table values
    for i in range(16):
        shiftedKeyLeft = shift_left(shiftedKeyLeft, leftShiftNumbers[i])
        shiftedKeyRight = shift_left(shiftedKeyRight, leftShiftNumbers[i])
        keyListLeft.append(shiftedKeyLeft)
        keyListRight.append(shiftedKeyRight)

    print("\nSubkeys created: ")
    print("Left: ", keyListLeft)
    print("Right:", keyListRight)

    # concatenating left and right keys and permuting them using PC-2
    concatList = []
    for i in range(16):
        concatList.append(keyListLeft[i] + keyListRight[i])

    subKeyList = []
    for i in range(16):
        permute = ""
        key = concatList[i]
        for j in range(48):
            index = PC2[j] - 1
            permute += key[index]
        subKeyList.append(permute)

    print("\nSubkeys permuted (48 bits): ")
    for i in range(16):
        printFor48(subKeyList[i])

    # now the 16 subkeys are ready
    # continuing with input (Feistel network) 
    # NOTE: comments represents the first round but it will be looped by 16 rounds    
    for roundNum in range(16):
        print("\n\nRound", roundNum, "starts...")
        # L1 = R0
        newLeft = right
        # R1 = L0 + f(R0,K1)
        # calculating result of f(R0,K1)
        res = ""
        for i in range(48):
            res += right[eBitSel[i] - 1]

        print("\nResult of the function: ")
        printFor48(res)
        # xor the result with LO
        XORed = xor(res, subKeyList[roundNum])
        print("\nAfter XORing key with function result: ")
        printFor48(XORed)

        # use s-tables. first divide binary into 8 equal pieces (divide by 6 since 48/6=8)
        divided = divideBinary(XORed, 6)
        # permute each 6 bit using s-table. we will 4x8 = 32 bit result
        permutedBin = ""
        for i in range(8):
            sixBit = divided[i]
            firstAndLastSum = divided[i][0] + divided[i][5]
            restSum = divided[i][1] + divided[i][2] + divided[i][3] + divided[i][4]
            row = int(firstAndLastSum, 2)
            col = int(restSum, 2)
            res = sTables[i][row][col]
            resBin = decToBinary4Bits(res)
            permutedBin += resBin

        print("\nPermuted bits using S-tables:")
        printWithSpace(permutedBin)

        # again permute with another permutation function
        newPermute = ""
        for i in range(32):
            index = Permutation[i] - 1
            newPermute += permutedBin[index]

        print("\nAgain permuted bits using P table. Result:")
        printWithSpace(newPermute)

        # XOR the result with left
        XORres = xor(newPermute, left)
        print("\nXORed permuted binary with left pair:")
        printWithSpace(XORres)
        right = XORres
        print("\n\nLeft", "round", roundNum + 1, "is:")
        printWithSpace(newLeft)
        print("Right", roundNum + 1, "is:")
        printWithSpace(right)
        left = newLeft

    # in the end of the 16 round we have L16 and R16
    # first, we need to swap them
    swap = right + left
    print("\nL16 and R16 swapped: ")
    printFor64(swap)

    # then permute with the reverse inital permutation table
    finalResult = ""
    for i in range(64):
        index = IPreverse[i] - 1
        finalResult += swap[index]

    print("\nFinal result as binary:")
    printFor64(finalResult)

    # convert it to ASCII code to find ciphertext
    cipherASCII = binary2ascii(finalResult)
    print("\nFinal result as ASCII code:")
    print(cipherASCII)
    print("\nECB round ", ECBr, "ends.\n")

    # convert hex ASCII to ordinary string (This is the ciphertext)
    cipherText = ascii2str(cipherASCII)
    print("\nCiphertext: \n", cipherText)
    listCT.append(cipherText)

print("\n\nAll ECB rounds are done. Printing ciphertext(s)...")
finalCipher = ""
for i in range(len(listCT)):
    print(i + 1, "-", listCT[i])
    finalCipher += listCT[i]

print("\nFinal cipher text: ", finalCipher)
print("Plain text: ", plainText)
print("Key: ", initialKey)