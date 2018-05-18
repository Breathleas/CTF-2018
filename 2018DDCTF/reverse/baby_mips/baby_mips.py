#!/usr/bin/env python
# coding=utf-8
from z3 import *
def convert2Negative(x):
    return (x - 0x100000000)

data = [35020L, 48287L, 58604L, 43156L, 12715L, 61001L, 8910L, 39296L, 11627L, 50802L, 26700L, 35884L, 20499L, 21074L, 14966L, 29932L, 16702L, 28166L, 34219L, 8190L, 60991L, 7093L, 44106L, 29205L, 38818L, 27556L, 45875L, 26269L, 64200L, 19005L, 21391L, 14145L, 54450L, 22447L, 47595L, 16257L, 60488L, 42494L, 3399L, 35521L, 7129L, 39605L, 12081L, 3919L, 23315L, 4738L, 56535L, 53508L, 35163L, 54987L, 44342L, 54948L, 55407L, 47074L, 34256L, 18105L, 28537L, 47489L, 18477L, 49870L, 48153L, 190L, 9242L, 47994L, 36972L, 51631L, 55151L, 49780L, 30018L, 18686L, 43592L, 37505L, 60137L, 2383L, 64516L, 41195L, 49703L, 2468L, 51666L, 22112L, 40953L, 12557L, 57436L, 13523L, 58229L, 54117L, 40950L, 41886L, 9485L, 21621L, 25649L, 38333L, 29184L, 46250L, 29852L, 40349L, 6406L, 41358L, 12192L, 37362L, 48683L, 11670L, 35937L, 62300L, 43105L, 42741L, 10643L, 53755L, 43949L, 11439L, 12257L, 51741L, 36283L, 33858L, 51128L, 45123L, 63889L, 30953L, 62200L, 37415L, 40401L, 37088L, 59767L, 3049L, 38171L, 59142L, 30041L, 41029L, 40903L, 39521L, 64650L, 17839L, 39943L, 40598L, 38917L, 12318L, 14000L, 2175L, 15057L, 8671L, 39991L, 55408L, 7758L, 21948L, 55321L, 46743L, 2153L, 63003L, 50298L, 46944L, 29785L, 27366L, 51041L, 22065L, 32487L, 14589L, 20675L, 41256L, 43944L, 38482L, 14965L, 13700L, 45917L, 20974L, 14385L, 32847L, 42013L, 33941L, 45030L, 40176L, 38763L, 56021L, 31558L, 57928L, 5780L, 65427L, 60637L, 39859L, 62412L, 38252L, 30047L, 16247L, 61163L, 47680L, 47674L, 50080L, 48117L, 16298L, 20378L, 18026L, 50947L, 63772L, 25912L, 9670L, 57512L, 41653L, 9398L, 2460L, 44421L, 28650L, 21109L, 43193L, 50015L, 38413L, 58836L, 15039L, 8813L, 9312L, 51692L, 63687L, 48712L, 37881L, 20315L, 43704L, 40004L, 30780L, 37414L, 23593L, 27855L, 59792L, 49753L, 20520L, 64888L, 62222L, 55297L, 17077L, 58222L, 21376L, 25367L, 23400L, 5327L, 8179L, 60223L, 33264L, 35758L, 51410L, 46263L, 51014L, 28656L, 6513L, 28139L, 42210L, 60835L, 48482L, 33000L, 64068L, 6265L, 10605L, 9556L, 50119L, 3553L, 28646L, 61773L, 30430L, 64066L, 45389L]
data = [35020L, 48287L, 58604L, 43156L, 12715L, 61001L, 8910L, 39296L, 11627L, 50802L, 26700L, 35884L, 20499L, 21074L, 14966L, 29932L, 16702L, 28166L, 34219L, 8190L, 60991L, 7093L, 44106L, 29205L, 38818L, 27556L, 45875L, 26269L, 64200L, 19005L, 21391L, 14145L, 54450L, 22447L, 47595L, 16257L, 60488L, 42494L, 3399L, 35521L, 7129L, 39605L, 12081L, 3919L, 23315L, 4738L, 56535L, 53508L, 35163L, 54987L, 44342L, 54948L, 55407L, 47074L, 34256L, 18105L, 28537L, 47489L, 18477L, 49870L, 48153L, 190L, 9242L, 47994L, 36972L, 51631L, 55151L, 49780L, 30018L, 18686L, 43592L, 37505L, 60137L, 2383L, 64516L, 41195L, 49703L, 2468L, 51666L, 22112L, 40953L, 12557L, 57436L, 13523L, 58229L, 54117L, 40950L, 41886L, 9485L, 21621L, 25649L, 38333L, 29184L, 46250L, 29852L, 40349L, 6406L, 41358L, 12192L, 37362L, 48683L, 11670L, 35937L, 62300L, 43105L, 42741L, 10643L, 53755L, 43949L, 11439L, 12257L, 51741L, 36283L, 33858L, 51128L, 45123L, 63889L, 30953L, 62200L, 37415L, 40401L, 37088L, 59767L, 3049L, 38171L, 59142L, 30041L, 41029L, 40903L, 39521L, 64650L, 17839L, 39943L, 40598L, 38917L, 12318L, 14000L, 2175L, 15057L, 8671L, 39991L, 55408L, 7758L, 21948L, 55321L, 46743L, 2153L, 63003L, 50298L, 46944L, 29785L, 27366L, 51041L, 22065L, 32487L, 14589L, 20675L, 41256L, 43944L, 38482L, 14965L, 13700L, 45917L, 20974L, 14385L, 32847L, 42013L, 33941L, 45030L, 40176L, 38763L, 56021L, 31558L, 57928L, 5780L, 65427L, 60637L, 39859L, 62412L, 38252L, 30047L, 16247L, 61163L, 47680L, 47674L, 50080L, 48117L, 16298L, 20378L, 18026L, 50947L, 63772L, 25912L, 9670L, 57512L, 41653L, 9398L, 2460L, 44421L, 28650L, 21109L, 43193L, 50015L, 38413L, 58836L, 15039L, 8813L, 9312L, 51692L, 63687L, 48712L, 37881L, 20315L, 43704L, 40004L, 30780L, 37414L, 23593L, 27855L, 59792L, 49753L, 20520L, 64888L, 62222L, 55297L, 17077L, 58222L, 21376L, 25367L, 23400L, 5327L, 8179L, 60223L, 33264L, 35758L, 51410L, 46263L, 51014L, 28656L, 6513L, 28139L, 42210L, 60835L, 48482L, 33000L, 64068L, 6265L, 10605L, 9556L, 50119L, 3553L, 28646L, 61773L, 30430L, 64066L, 45342L]

flag = [BitVec('u%d'%i,8) for i in range(16)]
fuhao =[
"+--++-+---++++-+",
"+---+-------++--",
"+-+-++--+--++-++",
"++-+--+-++++-+-+",
"+--+---++++---++",
"++-+-+--+++-+-++",
"++-++-+----++---",
"+--+-++-+++-++-+",
"+---+-+--+-+-+++",
"+-+++-++--+-+++-",
"+-------++--++--",
"+++++----+---+++",
"++++----++--+++-",
"+--+-+--+-++-+--",
"+-+--++--++-+--+",
"+++++-++++---+++"
]

print flag
s = Solver()
argu = []
for i in range(16):
    temp = []
    for j in range(0,16):    
        if(j==0):
            if(i==0 or i==2 or i==4 or i==7 or i==8 or i==13):
                temp.append(0-data[16*i])
            else:
                temp.append(data[16*i])
        else:
            if fuhao[i][j]=="+":
                temp.append(data[i*16+j])
            else:
                temp.append(data[i*16+j]*(-1))
    argu.append(temp)
print argu
for i in range(16):
    for j in range(16):
        print argu[i][j],
    print

value = [0xFF54530C, 0xFF604B34, 0x7ECDED, 0x4ACD04, 0xFFC0F0C9, 0xFF9D979F, 0x67309, 0x7E4CB2, 0xFF62497E, 0xAE4259, 0xFF685718, 0x754927, 0x87AC39, 0xFEE14C26, 0xFFF445A2, 0x133E993]
for i in range(16):
    if(value[i]>=0x80000000):
        value[i] = convert2Negative(value[i])
print value
s.add(argu[0][0]*flag[0]+argu[0][1]*flag[1]+argu[0][2]*flag[2]+argu[0][3]*flag[3]+argu[0][4]*flag[4]+argu[0][5]*flag[5]+argu[0][6]*flag[6]+argu[0][7]*flag[7]+argu[0][8]*flag[8]+argu[0][9]*flag[9]+argu[0][10]*flag[10]+argu[0][11]*flag[11]+argu[0][12]*flag[12]+argu[0][13]*flag[13]+argu[0][14]*flag[14]+argu[0][15]*flag[15]==value[0])

s.add(argu[1][0]*flag[0]+argu[1][1]*flag[1]+argu[1][2]*flag[2]+argu[1][3]*flag[3]+argu[1][4]*flag[4]+argu[1][5]*flag[5]+argu[1][6]*flag[6]+argu[1][7]*flag[7]+argu[1][8]*flag[8]+argu[1][9]*flag[9]+argu[1][10]*flag[10]+argu[1][11]*flag[11]+argu[1][12]*flag[12]+argu[1][13]*flag[13]+argu[1][14]*flag[14]+argu[1][15]*flag[15]==value[1])

s.add(argu[2][0]*flag[0]+argu[2][1]*flag[1]+argu[2][2]*flag[2]+argu[2][3]*flag[3]+argu[2][4]*flag[4]+argu[2][5]*flag[5]+argu[2][6]*flag[6]+argu[2][7]*flag[7]+argu[2][8]*flag[8]+argu[2][9]*flag[9]+argu[2][10]*flag[10]+argu[2][11]*flag[11]+argu[2][12]*flag[12]+argu[2][13]*flag[13]+argu[2][14]*flag[14]+argu[2][15]*flag[15]==value[2])

s.add(argu[3][0]*flag[0]+argu[3][1]*flag[1]+argu[3][2]*flag[2]+argu[3][3]*flag[3]+argu[3][4]*flag[4]+argu[3][5]*flag[5]+argu[3][6]*flag[6]+argu[3][7]*flag[7]+argu[3][8]*flag[8]+argu[3][9]*flag[9]+argu[3][10]*flag[10]+argu[3][11]*flag[11]+argu[3][12]*flag[12]+argu[3][13]*flag[13]+argu[3][14]*flag[14]+argu[3][15]*flag[15]==value[3])

s.add(argu[4][0]*flag[0]+argu[4][1]*flag[1]+argu[4][2]*flag[2]+argu[4][3]*flag[3]+argu[4][4]*flag[4]+argu[4][5]*flag[5]+argu[4][6]*flag[6]+argu[4][7]*flag[7]+argu[4][8]*flag[8]+argu[4][9]*flag[9]+argu[4][10]*flag[10]+argu[4][11]*flag[11]+argu[4][12]*flag[12]+argu[4][13]*flag[13]+argu[4][14]*flag[14]+argu[4][15]*flag[15]==value[4])

s.add(argu[5][0]*flag[0]+argu[5][1]*flag[1]+argu[5][2]*flag[2]+argu[5][3]*flag[3]+argu[5][4]*flag[4]+argu[5][5]*flag[5]+argu[5][6]*flag[6]+argu[5][7]*flag[7]+argu[5][8]*flag[8]+argu[5][9]*flag[9]+argu[5][10]*flag[10]+argu[5][11]*flag[11]+argu[5][12]*flag[12]+argu[5][13]*flag[13]+argu[5][14]*flag[14]+argu[5][15]*flag[15]==value[5])

s.add(argu[6][0]*flag[0]+argu[6][1]*flag[1]+argu[6][2]*flag[2]+argu[6][3]*flag[3]+argu[6][4]*flag[4]+argu[6][5]*flag[5]+argu[6][6]*flag[6]+argu[6][7]*flag[7]+argu[6][8]*flag[8]+argu[6][9]*flag[9]+argu[6][10]*flag[10]+argu[6][11]*flag[11]+argu[6][12]*flag[12]+argu[6][13]*flag[13]+argu[6][14]*flag[14]+argu[6][15]*flag[15]==value[6])

s.add(argu[7][0]*flag[0]+argu[7][1]*flag[1]+argu[7][2]*flag[2]+argu[7][3]*flag[3]+argu[7][4]*flag[4]+argu[7][5]*flag[5]+argu[7][6]*flag[6]+argu[7][7]*flag[7]+argu[7][8]*flag[8]+argu[7][9]*flag[9]+argu[7][10]*flag[10]+argu[7][11]*flag[11]+argu[7][12]*flag[12]+argu[7][13]*flag[13]+argu[7][14]*flag[14]+argu[7][15]*flag[15]==value[7])

s.add(argu[8][0]*flag[0]+argu[8][1]*flag[1]+argu[8][2]*flag[2]+argu[8][3]*flag[3]+argu[8][4]*flag[4]+argu[8][5]*flag[5]+argu[8][6]*flag[6]+argu[8][7]*flag[7]+argu[8][8]*flag[8]+argu[8][9]*flag[9]+argu[8][10]*flag[10]+argu[8][11]*flag[11]+argu[8][12]*flag[12]+argu[8][13]*flag[13]+argu[8][14]*flag[14]+argu[8][15]*flag[15]==value[8])

s.add(argu[9][0]*flag[0]+argu[9][1]*flag[1]+argu[9][2]*flag[2]+argu[9][3]*flag[3]+argu[9][4]*flag[4]+argu[9][5]*flag[5]+argu[9][6]*flag[6]+argu[9][7]*flag[7]+argu[9][8]*flag[8]+argu[9][9]*flag[9]+argu[9][10]*flag[10]+argu[9][11]*flag[11]+argu[9][12]*flag[12]+argu[9][13]*flag[13]+argu[9][14]*flag[14]+argu[9][15]*flag[15]==value[9])

s.add(argu[10][0]*flag[0]+argu[10][1]*flag[1]+argu[10][2]*flag[2]+argu[10][3]*flag[3]+argu[10][4]*flag[4]+argu[10][5]*flag[5]+argu[10][6]*flag[6]+argu[10][7]*flag[7]+argu[10][8]*flag[8]+argu[10][9]*flag[9]+argu[10][10]*flag[10]+argu[10][11]*flag[11]+argu[10][12]*flag[12]+argu[10][13]*flag[13]+argu[10][14]*flag[14]+argu[10][15]*flag[15]==value[10])

s.add(argu[11][0]*flag[0]+argu[11][1]*flag[1]+argu[11][2]*flag[2]+argu[11][3]*flag[3]+argu[11][4]*flag[4]+argu[11][5]*flag[5]+argu[11][6]*flag[6]+argu[11][7]*flag[7]+argu[11][8]*flag[8]+argu[11][9]*flag[9]+argu[11][10]*flag[10]+argu[11][11]*flag[11]+argu[11][12]*flag[12]+argu[11][13]*flag[13]+argu[11][14]*flag[14]+argu[11][15]*flag[15]==value[11])

s.add(argu[12][0]*flag[0]+argu[12][1]*flag[1]+argu[12][2]*flag[2]+argu[12][3]*flag[3]+argu[12][4]*flag[4]+argu[12][5]*flag[5]+argu[12][6]*flag[6]+argu[12][7]*flag[7]+argu[12][8]*flag[8]+argu[12][9]*flag[9]+argu[12][10]*flag[10]+argu[12][11]*flag[11]+argu[12][12]*flag[12]+argu[12][13]*flag[13]+argu[12][14]*flag[14]+argu[12][15]*flag[15]==value[12])

s.add(argu[13][0]*flag[0]+argu[13][1]*flag[1]+argu[13][2]*flag[2]+argu[13][3]*flag[3]+argu[13][4]*flag[4]+argu[13][5]*flag[5]+argu[13][6]*flag[6]+argu[13][7]*flag[7]+argu[13][8]*flag[8]+argu[13][9]*flag[9]+argu[13][10]*flag[10]+argu[13][11]*flag[11]+argu[13][12]*flag[12]+argu[13][13]*flag[13]+argu[13][14]*flag[14]+argu[13][15]*flag[15]==value[13])

s.add(argu[14][0]*flag[0]+argu[14][1]*flag[1]+argu[14][2]*flag[2]+argu[14][3]*flag[3]+argu[14][4]*flag[4]+argu[14][5]*flag[5]+argu[14][6]*flag[6]+argu[14][7]*flag[7]+argu[14][8]*flag[8]+argu[14][9]*flag[9]+argu[14][10]*flag[10]+argu[14][11]*flag[11]+argu[14][12]*flag[12]+argu[14][13]*flag[13]+argu[14][14]*flag[14]+argu[14][15]*flag[15]==value[14])

s.add(argu[15][0]*flag[0]+argu[15][1]*flag[1]+argu[15][2]*flag[2]+argu[15][3]*flag[3]+argu[15][4]*flag[4]+argu[15][5]*flag[5]+argu[15][6]*flag[6]+argu[15][7]*flag[7]+argu[15][8]*flag[8]+argu[15][9]*flag[9]+argu[15][10]*flag[10]+argu[15][11]*flag[11]+argu[15][12]*flag[12]+argu[15][13]*flag[13]+argu[15][14]*flag[14]+argu[15][15]*flag[15]==value[15])

s.check()

result = s.model()
print result

ddctf = ""
for i in range(16):
    ddctf += chr(result[flag[i]].as_long())

print ddctf
