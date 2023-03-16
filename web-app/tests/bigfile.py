import math
import sys

# Generate a lot of text
# For example, to make an 8 GiB file:
# python bigfile.py $(( 2 ** 33 )) > big.txt
def bigfile(size):
  power = math.ceil(math.log(size)/math.log(2))
  octets_per_word = max(1, power - 3)
  for x in range(octets_per_word - 1, size, octets_per_word):
     print(f'%0{octets_per_word}x' % x, end = '')


if __name__== "__main__":
    bigfile(int(sys.argv[1]))
