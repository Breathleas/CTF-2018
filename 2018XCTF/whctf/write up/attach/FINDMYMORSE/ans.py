s = [0xa7 ,0xd6 ,0x61 ,0xb5 ,0x6e ,0xbb ,0xba ,0xe3 ,0xa9 ,0xdd ,0xc4 ,0x77 ,0x6f ,0xee ,0xec ,0xff ,0x62 ,0xc3 ,0xcf ,0xda ,0x53 ,0xce ,0xff ,0x71 ,0x71 ,0x14 ,0xff ,0xf2]
ans = '' 
count = 0
t = 0
print '------------- new round -------------'
for i in range(7):
	for m in range(8):
		for j in range(4):
			t = t<<1
			t += s[j*7+i]&1
			print j,i,s[j*7+i],s[j*7+i]&1,t,hex(j*7+i)
			s[j*7+i] = s[j*7+i] >> 1
			count += 1
			if count == 7:
				print hex(t)
				print '------------- new round -------------'
				ans += chr(t)
				count = 0
				t = 0
print ans