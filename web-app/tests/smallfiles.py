#!/usr/bin/env python3

import math
import sys


# Generate a lot of smallish files
# For example, to make an 1,024 file:
# python bigfile.py $(( 2 ** 10 ))
def fill(f, size):
    power = math.ceil(math.log(size) / math.log(2))
    octets_per_word = max(1, power - 3)
    strides = size // octets_per_word
    remainder = size % octets_per_word
    for x in range(strides):
        f.write(f"%0{octets_per_word}x" % (x * octets_per_word))
    for x in range(remainder):
        f.write(".")


if __name__ == "__main__":
    n = int(sys.argv[1])
    digits = math.ceil(math.log(n+1) / math.log(10))
    for x in range(1, n + 1):
        infix = f"{x}".rjust(digits, "0")
        with open(f"s-{infix}.txt", "w") as file:
            fill(file, x)
