p = 28151
g = 2
ans = False

while not ans:
    for n in range (2,p):
        if pow (g,n,p) == 1:
            break
        if n == p - 2:
            print(g)
            ans = True
    g = g + 1