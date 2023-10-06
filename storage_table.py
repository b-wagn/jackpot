#!/usr/bin/env python

import math
import sys
import csv
from tabulate import tabulate



# we assume curve BLS12-381 is used
# one group element has size 48 Bytes
# field element / exponent has 32 Bytes
FE_SIZE = 32.0
GE_SIZE = 48.0


# the range of ticket numbers we compare
RANGE = [1,16,256,1024,2048]


# we compare our lottery scheme to BLS+Hash
# for both we define a function how much space is needed
# to store/transmit a given number of winning tickets
def storage_bls(num_tickets):
	# a winning ticket is just a BLS signature
	# and we can not aggregate them
	return num_tickets*GE_SIZE

def storage_ours(num_tickets):
	# if we aggregate that many tickets,
	# we get one ticket, which is just
	# a KZG opening proof, i.e., one
	# field element and one group element
	return GE_SIZE+FE_SIZE




# Assemble the table
table = [["L","BLS-H", "Jack", "Ratio"]]

for nt in RANGE:
	bls = storage_bls(nt)
	ours = storage_ours(nt)
	ratio = bls/ours
	row = [nt,bls,ours,ratio]
	table.append(row)

print(tabulate(table,headers='firstrow',tablefmt='fancy_grid'))
