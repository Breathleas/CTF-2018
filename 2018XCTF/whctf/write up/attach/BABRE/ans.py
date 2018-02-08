s = '\x66\x6d\x63\x64\x7f\x6b\x37\x64\x3b\x56\x60\x3b\x6e\x70'

s = list(s)
for i in range(len(s)):
	s[i] = chr(ord(s[i])^i)

print ''.join(s)