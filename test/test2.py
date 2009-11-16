# -*- coding: utf-8 -*-
from numpy import arange,sqrt, random, linalg
from multiprocessing import Pool

global counter
counter = 0
def cb(r):
    global counter
    print counter, r
    counter +=1
    
def det(M):
    return linalg.det(M)

po = Pool()
for i in xrange(1,300):
    j = random.normal(1,1,(100,100))
    po.apply_async(det,(j,),callback=cb)
po.close()
po.join()
print counter
