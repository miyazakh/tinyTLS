import random

def RsaGenKey(min):

    def prime(max):
        counter = 0
        primes = [2, 3]
        for n in range(5, max, 2):
          isprime = True
          for i in range(1, len(primes)):
            counter += 1
            if n % primes[i] == 0:
              isprime = False
              break
          if isprime:
            primes.append(n)
        return primes
    def gcd(a, b):
      while b:
        a, b = b, a % b
      return a
    def lcm(x, y):
      return x * y // gcd(x, y)

    primes = prime(1000)
    while True:
        q = primes[random.randint(1, len(primes)-1)]
        p_index = random.randint(1, len(primes)-2)
        p = primes[p_index]
        if p != q: break
    n = p * q
    while(n < min):
        p_index += 1
        p = primes[p_index]
        n = p * q
    l = lcm(p-1, q-1)
    while True:
        i = random.randint(2, l)
        if gcd(i, l) == 1:
            e = i
            break
    while True:
        i = random.randint(2, l)
        if(e*i)%l == 1:
            d = i
            break
    return (e, n), (d, n)
