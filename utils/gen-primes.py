'''
Script to generate (n) prime numbers, outputs as JSON array 

Used to pre-compute prime numbers for small prime sieving 
'''
import json 
import os 
from math import sqrt 

def primes(n):
    if n < 1: 
        return []
    ret = [2]
    i = 3

    while len(ret) < n: 
        top = int(sqrt(i)) + 1
        is_prime = True

        for j in range(2, top):
            if i % j == 0: 
                is_prime = False 
                break 
        
        if is_prime: 
            ret.append(i)

        i += 2
    return ret 







def main():
    p = int(input("Enter the number of primes to compute: ")) 
    file = input("Enter the output file location (default ./primes.json): ")

    if file == "":
        file = './primes.json'

    print("Generating the first {} primes, outputting at {}".format(p, file))
    lst = primes(p)

    with open(file, 'w') as f: 
        json.dump(lst, f)


if __name__ == '__main__': 
    main()
