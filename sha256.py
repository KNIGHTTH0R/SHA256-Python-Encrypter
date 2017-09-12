# implementation of SHA 256 hash generator in python.


# taking the input message to be used for hashing
msg = raw_input("Enter your message:")
msg_length = len(msg)
#print msg, msg_length


# converting the message into binary format
binary_name = ''.join('{0:08b}'.format(ord(x), 'b') for x in msg)
binary_name_length = len(binary_name)
#print "Name in binary:", binary_name, binary_name_length


# creating a 512 bit message block by padding
zeros = 448 % 512 - (binary_name_length + 1)
#print zeros
k = '0' * zeros
#print len(k)
binary_length = '{0:064b}'.format(binary_name_length)
#print binary_length, len(binary_length)
msg_512 = binary_name + '1' + k + binary_length
#print msg_512, len(msg_512)


# breaking the 512 bit message block into 16 32 bit blocks [therefore, 1 block = 32 bit words]
# M(0),M(1),.....,M(15)
M = [msg_512[i:i + 32] for i in range(0,511,32)]
#print M	


# declaring the inital hash values to be used
H = ['6a09e667','bb67ae85','3c6ef372','a54ff53a','510e527f','9b05688c','1f83d9ab','5be0cd19']  # [a, b, c, d, e, f, g, h]
F = []
F.append(H)
#print F

K = ['428a2f98','71374491','b5c0fbcf','e9b5dba5','3956c25b','59f111f1','923f82a4','ab1c5ed5','d807aa98','12835b01','243185be','550c7dc3','72be5d74','80deb1fe','9bdc06a7', 'c19bf174','e49b69c1','efbe4786','0fc19dc6','240ca1cc','2de92c6f','4a7484aa','5cb0a9dc','76f988da','983e5152','a831c66d','b00327c8','bf597fc7','c6e00bf3','d5a79147', '06ca6351','14292967','27b70a85','2e1b2138','4d2c6dfc','53380d13','650a7354','766a0abb','81c2c92e','92722c85','a2bfe8a1','a81a664b','c24b8b70','c76c51a3', 'd192e819', 'd6990624','f40e3585','106aa070','19a4c116','1e376c08','2748774c','34b0bcb5','391c0cb3','4ed8aa4a','5b9cca4f','682e6ff3','748f82ee','78a5636f','84c87814','8cc70208',
'90befffa','a4506ceb','bef9a3f7','c67178f2']
#print len(K)


mask = 2 ** 32 - 1
# defining 6 logical functions which are used for hash generation
def ch(x, y, z):
	op1 = (x & y) ^ (~x & z)	
	return op1

def ma(x, y, z):
	op2 = (x & y) ^ (x & z) ^ (y & z)
	return op2
	
def sum0(x):
	rr1 = (x >> 2) | ((x << 30) & mask)
	rr2 = (x >> 13) | ((x << 19) & mask)
	rr3 = (x >> 22) | ((x << 10) & mask)
	rr = rr1 ^ rr2 ^ rr3
	return rr

def sum1(x):
	rr1 = (x >> 6) | ((x << 26) & mask)
	rr2 = (x >> 11) | ((x << 21) & mask)
	rr3 = (x >> 25) | ((x << 7) & mask)
	rr = rr1 ^ rr2 ^ rr3
	return rr

def sig0(x):
	rr1 = (x >> 7) | ((x << 25) & mask)
	rr2 = (x >> 18) | ((x << 14) & mask)
	rr3 = x >> 3
	rr = rr1 ^ rr2 ^ rr3
	return rr

def sig1(x):
	rr1 = (x >> 17) | ((x << 15) & mask)
	rr2 = (x >> 19) | ((x << 13) & mask)
	rr3 = x>> 10
	rr = rr1 ^ rr2 ^ rr3
	return rr


# looping from N: 1 to 16 

modes = 2 ** 32
W = [0 for i in range(64)]

for i in range(1,17):

	# initializing the registers 
	a = int(F[i-1][0], base = 16)
	b = int(F[i-1][1], base = 16)
	c = int(F[i-1][2], base = 16)
	d = int(F[i-1][3], base = 16)
	e = int(F[i-1][4], base = 16)
	f = int(F[i-1][5], base = 16)
	g = int(F[i-1][6], base = 16)
	h = int(F[i-1][7], base = 16)

	# looping from M:0 to 63 [64 words generated per block of 32 bit words]
	for j in range(0,64):

		if j >= 16:  # the remaining range M:16 to 63 are generated using a formula
			W[j] = (((((sig1(W[j - 2]) + W[j - 7]) % modes) + sig0(W[j - 15])) % modes) + W[j - 16]) % modes        
		else:  # for the range M:0 to 15 the 32 bit words same as initial 16 block words i.e. M(0),M(1),...,M(15)
			W[j] = int(M[j], base = 2) 
		

		t1 = (((((((h + sum1(e)) % modes) + ch(e,f,g)) % modes) + int(K[j], base = 16)) % modes) + W[j]) % modes
		t2 = (sum0(a) + ma(a,b,c)) % modes
		h = g
		g = f
		f = e
		e = (d + t1) % modes
		d = c
		c = b
		b = a
		a = (t1 + t2) % modes

		#print '{0:08x}'.format(a, '0x'),'{0:08x}'.format(b, '0x'),'{0:08x}'.format(c, '0x'),'{0:08x}'.format(d, '0x'),'{0:08x}'.format(e, '0x'),'{0:08x}'.format(f, '0x'),'{0:08x}'.format(g, '0x'),'{0:08x}'.format(h, '0x')                                    


	H[0] = '{0:08x}'.format(((a + int(F[i-1][0], base = 16)) % modes), '0x')
	H[1] = '{0:08x}'.format(((b + int(F[i-1][1], base = 16)) % modes), '0x')
	H[2] = '{0:08x}'.format(((c + int(F[i-1][2], base = 16)) % modes), '0x')
	H[3] = '{0:08x}'.format(((d + int(F[i-1][3], base = 16)) % modes), '0x')
	H[4] = '{0:08x}'.format(((e + int(F[i-1][4], base = 16)) % modes), '0x')
	H[5] = '{0:08x}'.format(((e + int(F[i-1][5], base = 16)) % modes), '0x')
	H[6] = '{0:08x}'.format(((g + int(F[i-1][6], base = 16)) % modes), '0x')
	H[7] = '{0:08x}'.format(((h + int(F[i-1][7], base = 16)) % modes), '0x')
	F.append(H)
	print  H[0],H[1],H[2],H[3],H[4],H[5],H[6],H[7]

print 
hashed = ''.join(H[i] for i in range(8))
print "Hash:",hashed

