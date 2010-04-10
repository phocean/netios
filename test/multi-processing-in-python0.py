import multiprocessing

def testing(arg):
    x = 0
    for i in xrange(arg):
        x += i * i
    return x

if __name__ == "__main__":
    pool = multiprocessing.Pool(N_PROCESSES)
    print "processing..."
    results = pool.map(testing, range(20000000))
    print results
