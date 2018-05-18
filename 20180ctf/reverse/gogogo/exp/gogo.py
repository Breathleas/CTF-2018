
def func6(a):
	t0 = len(a)	#0
	t1 = [0]*t0
	t2 = len(a)
	t3 = t1-1

	while True:
		t8 = phi[0:t1, 5:t15]	#3
		t9 = phi[0:t3, 5:t16]
		if t9 >= 0:
			t4 = a[t9]	#1
			t5 = t4 - 48
			t6 = ord(t5)
			if t6 >= 0:
				if t6 < 10: #6
					t13 = [t6]	#4
					t14 = append(t8,t13)

			t15 = phi[1:t8, 6:t8, 4:t14] 	#5
			t16 = t9-1
		else:
			return t8 	#2

def func1(aa,bb): 		#check
	t0 = len(aa) #0
	t1 = t0-1

	t8 = phi[0:t1, 5:t12]	#3
	if t8 >=0:
		t2 = aa[t8:] 	#1
		t3 = aa[t8]
		if t3 > 0:

			t10 = t8+1		#4
			t11 = aa[:t10]
	
	t5 = phi[2:t7, 10:t24]		#2
	t6 = len(bb)
	t7 = t6-1

	while True:
		t20 = phi[2:t7, 10:t24] #8
		if t20 >=0 :

			t13 = bb[t20:]	#6
			t14 = bb[t20]
			if t14 > 0:

				pass		#9
			else:
				t24 = t20-1		#10
		else:
			
			t16 = phi[8:nil:[]int, 9:t23]					#7
			t17 = len(t5)
			t18 = len(t16)

			if t17 > t18:
				return 1		#11
			else:
				return 0		#12


def func0(a,b):	#max
	if a > b:
		return a
	else:
		return b

def func2(a,b):
	t0 = len(a)		#0
	t1 = len(b)
	t2 = func0(t0,t1)
	t3 = t2+1
	t4 = [t3]*t3
	t5 = len(t4)

	while True:
		t6 = phi[0:0, 9:t22]			#1
		t7 = phi[0:-1, 9:t8]
		t8 = t7+1
		if t8 < t5:

			t10 = len(a)	#2
			if t8 < t10:

				t12 = a[t8:]		#4
				t13 = a[t8]

			else

				t14 = phi[2:0, 4:t13]					#5
				t15 = len(b)
				if t8 < t15:

					t17 = b[t8:]	#6
					t18 = b[t8]

				t19 = phi[5:0, 6:t18] 	#7
				t20 = t14+t19
				t21 = t20+t6
				t22 = t21/10
				if t21>=10:

					t24 = t21%10		#8

				t25 = phi[7:t21, 8:t24]		#9
				t26 = t4[t8:]
				t4[t8] = t25
		else:
			
			return t4		#3

def func4(a,b):
	t0 = len(a)		#0
	t1 = len(b)
	t2 = t0 + t1
	t3 = [t2]*t2
	t4 = len(t3)

	while True:
		t5 = phi[0:-1, 2:t6]	#1	
		t6 = t5+1
		if t6 < t4:

			t8	= t3[t6:]		#2
			t8[0] = 0

		else:

			t13 = phi[3:0, 8:t26]	#3 -> 6
			t14 = len(b)
			if t13 < t14:

				while True:
					t27 = phi[4:0, 7:t25]			#4 -> 9
					t28 = len(a)
					if t27 < t28:

						t16 = a[t27:]			#7
						t17 = t16[0]
						t18 = b[t13:]
						t19 = t18[0]
						t20 = t17*t19
						t21 = t13+t27
						t22 = t3[t21:]
						t23 = t22[0]
						t24 = t23+t20
						t22[0] = t24
						t25 = t27+1
					else:

						t26 = t13+1			#8
						break
			else:

				t9 = len(t3)		#5
				t10 = t9-1
				t11 = t3[:t10]
				t2 = len(t11)

				while True:
					t30 = phi[5:-1, 11:t32, 13:t31]		#10
					t31 = t30+1
					if t31 < t12:

						t33 = t3[t31:]	#11
						t34 = t33[0]
						if t34 >= 10:

							t36 = t31+1		#13
							t37 = t3[t36:]
							t38 = t3[t31:]
							t39 = t38[0]
							t40 = t39/10
							t41 = t37[0]
							t42 = t41+t40
							t37[0] = t42
							t43 = t3[t31:]
							t44 = t43[0]
							t45 = t44%10
							t43[0] = t45.

					else：

						return t3 	#12

def func4(a, b):
	table = [0 for i in range(len(a) + len(b))]
	for i in range(len(a)):
		for j in range(len(b)):
			table[i+j] += a[i] * b[j]
	for i in range(len(table)-1):
		table[i+1] = table[i] / 10 + table[i+1]
		table[i] = table[i] % 10
	return table

#main
print "Input 3 numbers"
t12 = input()
t17 = input()
t22 = input()

t24 = func6(t0) #sa
t26 = func6(t1) #sb
t28 = func6(t2) #sc

t29 = len(t24)

if t29 == 0:
	exit(0)
else:
	t43 = len(t26)
	if t43 == 0:
		exit(0)
	else:
		t41 = len(28)
		if t41 == 0:
			exit(0)
		else:
			t36 = [0]
			t39 = func1(t24,t36)

			if t39<=0:
				exit(0)
			else:
				t74 = [0]
				t77 = func1(t26,t74)

				if t77 <= 0:
					exit(0)
				else:
					t69 = [0]
					t72 = func1(t28,t71)

					if t72 <= 0:
						exit(0)
					else:
						t50 = func2(t24,t26)
						t51 = func2(t24,t28)
						t52 = func2(t26,t28)

						t53 = func4(t50,t51)
						t54 = func4(t53,t24)
						t55 = func4(t50,t52)
						t56 = func4(t55,t26)
						t57 = func4(t51,t52)
						t58 = func4(t57,t28)

						t59 = func2(t56,t58)
						t60 = func2(t54,t59)

						t61 = [10]
						t64 = func4(t51,t52)
						t65 = func4(t50,t64)
						t66 = func4(t61,t65)
						t67 = func1(t60,t66)

						if t67 == 0:
							print 'Congratulations'
						else:
							print "Wrong! Try again!!"

