import math
import binascii
import gmpy2

def extent_Euclid(a,b):#扩展欧几里得算法，用来求使得ae1+be2=1modn中的(a,b)
    if a>b:
        (x1,x2,x3)=(1,0,a)
        (y1,y2,y3)=(0,1,b)
        while y3!=0:
            q=x3//y3
            (t1,t2,t3)=(x1-q*y1,x2-q*y2,x3-q*y3)
            (x1,x2,x3)=(y1,y2,y3)
            (y1,y2,y3)=(t1,t2,t3)
        return (x1,x2)
    else:
        (a,b)=(b,a)
        (x1,x2,x3)=(1,0,a)
        (y1,y2,y3)=(0,1,b)
        while y3!=0:
            q=x3//y3
            (t1,t2,t3)=(x1-q*y1,x2-q*y2,x3-q*y3)
            (x1,x2,x3)=(y1,y2,y3)
            (y1,y2,y3)=(t1,t2,t3)
        return (x2,x1)

def same_mod():#公共模数攻击
    for i in range(21):
        for j in range(i+1,21):
            if n[i]==n[j]:
                print("Frame{}".format(i)+"和Frame{}存在公共模数".format(j))
                x,y=extent_Euclid(int(e[i],16),int(e[j],16))#求使得a*e1+b*e2=1modn中的(a,b)
                m=pow(int(c[i],16),x,int(n[i],16))*pow(int(c[j],16),y,int(n[i],16))%int(n[i],16)#m=c1^a+c2^b=m^(a*e1+b*e2)
                print('明文切片为：',hex(m))
                print("恢复出的明文为:",binascii.a2b_hex(hex(m)[-16:]).decode())
                #因为解密出的明文的最后十六位（十六进制数）为明文分片字符对应的 ASCII 码，所以只取m的后16位
                m_decrypt[i]["明文"]=m_decrypt[j]["明文"]=str(binascii.a2b_hex(hex(m)[-16:]).decode())

def factor_collision():#因数碰撞攻击
    for i in range(21):
        for j in range(i+1,21):
            if(n[i]!=n[j] and math.gcd(int(n[i],16),int(n[j],16))!=1):
                print("Frame{}".format(i) + "和Frame{}的模数存在公共因数".format(j))
                p=math.gcd(int(n[i],16),int(n[j],16))#定义p位公共因数
                q_i = int(n[i], 16) // p#q等于n整除p
                q_j = int(n[j], 16) // p
                phi_i = (p-1) * (q_i-1)#求φ（n）
                phi_j = (p-1) * (q_j-1)
                d_i = pow(int(e[i], 16), -1, phi_i)#求e的模逆d，私钥
                d_j = pow(int(e[j], 16), -1, phi_j)
                m_i = pow(int(c[i], 16), d_i, int(n[i], 16))
                m_j = pow(int(c[j], 16), d_j, int(n[j], 16))
                print("Frame{}".format(i) + '参数p：', hex(p))
                print("Frame{}".format(i) + '参数q：', hex(q_i))
                print("Frame{}".format(i) + '私钥d：', hex(d_i))
                print("Frame{}".format(i) + '明文切片为：',hex(m_i))
                print("Frame{}".format(i) + "恢复出的明文为:", binascii.a2b_hex(hex(m_i)[-16:]).decode())

                print("Frame{}".format(j) + '参数p：', hex(p))
                print("Frame{}".format(j) + '参数q：', hex(q_j))
                print("Frame{}".format(j) + '私钥d：', hex(d_j))
                print("Frame{}".format(j) + '明文切片为：', hex(m_j))
                print("Frame{}".format(j) + "恢复出的明文为:", binascii.a2b_hex(hex(m_j)[-16:]).decode())
                m_decrypt[i]["明文"] = str(binascii.a2b_hex(hex(m_i)[-16:]).decode())
                m_decrypt[j]["明文"] = str(binascii.a2b_hex(hex(m_j)[-16:]).decode())

def fermat(n):#费马分解n为p、q
    a = gmpy2.isqrt(n)
    b2 = a*a - n
    b = gmpy2.isqrt(n)
    count = 0
    while b*b != b2 and count<1000000:
        a = a + 1
        b2 = a*a - n
        b = gmpy2.isqrt(b2)
        count += 1
    p=a+b
    q=a-b
    return p,q

def fermat_resolve(a):#费马分解法
    p,q=fermat(int(n[a],16))#p、q
    phi=(p-1)*(q-1)#φ(n)
    d=pow(int(e[a],16),-1,phi)#私钥
    m=pow(int(c[a],16),d,int(n[a],16))
    print("Frame{}".format(a) + '参数p：', hex(p))
    print("Frame{}".format(a) + '参数q：', hex(q))
    print("Frame{}".format(a) + '私钥d：', hex(d))
    print("Frame{}".format(a) + '明文切片为：', hex(m))
    print("Frame{}".format(a) + "恢复出的明文为:", binascii.a2b_hex(hex(m)[-16:]).decode())
    m_decrypt[a]["明文"] = str(binascii.a2b_hex(hex(m)[-16:]).decode())

def pollard(n):#Pollar分解n输出p
    m = 2
    max = n
    for i in range(max):
        if i>0:
            m = pow(m,i,n)
            if (math.gcd(n,m-1) != 1):
                return math.gcd(n,m-1)

def pollard_resolve(a):#Pollard p-1分解法
    p = pollard(int(n[a], 16))
    q = int(n[a], 16) // p
    phi = (p-1)*(q-1)
    d = gmpy2.invert(int(e[a], 16), phi)
    m = gmpy2.powmod(int(c[a], 16), d, int(n[a], 16))
    print("Frame{}".format(a) + '参数p：', hex(p))
    print("Frame{}".format(a) + '参数q：', hex(q))
    print("Frame{}".format(a) + '私钥d：', hex(d))
    print("Frame{}".format(a) + '明文切片为：', hex(m))
    print("Frame{}".format(a) + "恢复出的明文为:", binascii.a2b_hex(hex(m)[-16:]).decode())
    m_decrypt[a]["明文"] = str(binascii.a2b_hex(hex(m)[-16:]).decode())

def chinese_remain(c_list,n_list):#中国剩余定理
    a=c_list
    m=n_list
    M={}
    M_invert={}#M的逆元
    x={}

    flag=0#记录能否直接运用中国剩余定理
    for i in range(len(m)):
        for j in range(len(m)):
            if(i!=j and math.gcd(m[i],m[j])!=1):#若存在两个不同的m不互素，flag置1
                flag=1
                break

    if flag:
        print("不能直接利用中国剩余定理")
    else:
        m_all=1
        for i in range(len(m)):
            m_all*=m[i]

        for i in range(len(m)):
            M[i]=int(m_all//m[i])#运用//（整数除法）而不是/（除法），保证Mi为整数而不是浮点数
            M_invert[i]=pow(M[i],-1,m[i])
            x[i]=(M[i]*M_invert[i]*a[i])%m_all

        result=0
        for i in range(len(m)):
            result+=x[i]

        result=(result)%m_all
        return result

def low_encrypt_exp(a):#低加密指数攻击
    no_list=[]
    c_list=[]
    n_list=[]
    for i in range(21):
        if int(e[i],16)==a:#当指数为输入的小整数时，将对应的密文和模数存储
            no_list.append(i)
            c_list.append(int(c[i],16))
            n_list.append(int(n[i],16))
    m_exp=chinese_remain(c_list,n_list)
    m=gmpy2.iroot(gmpy2.mpz(m_exp),a)
    print('明文切片为：',hex(m[0]))
    print("指数为{}时，".format(a)+"Frame{}".format(no_list)+"恢复出的明文为:{}".format(binascii.a2b_hex(hex(m[0])[-16:]).decode()))
    for i in no_list:
        m_decrypt[i]["明文"] = str(binascii.a2b_hex(hex(m[0])[-16:]).decode())


n = []#模数
c = []#密文
e = []#公钥
m_decrypt=[{"Frame":i,"明文":""} for i in range(21)]#明文
for i in range(21):
    f=open("Frame"+str(i),'r')
    data= f.read()
    n.append(data[0:256])
    e.append(data[256:512])
    c.append(data[512:768])

#print("\n分离出的各帧中数据为：")
#for i in range(21):
#    print('Frame',i)
#    print('N=',n[i])
#    print('e=',e[i])
#    print('c=',c[i])

print("\n公共模数攻击破译出：")
same_mod()
print("\n因数碰撞法破译出：")
factor_collision()
print("\n低加密指数攻击破译出：")
low_encrypt_exp_list=[5]
for i in low_encrypt_exp_list:
    low_encrypt_exp(i)

print("\n费马分解法攻击破译出：")
fermat_list=[10]
for i in fermat_list:
    fermat_resolve(i)
print("\nPollar p-1法破译出：")
pollard_list=[2,6,19]
for i in pollard_list:
    pollard_resolve(i)


print("\n截至目前，所有帧对应的明文如下：")
for i in range(21):
    print(m_decrypt[i])

#最终明文经排序、搜索、补全后，得到’My secret is a famous saying of Albert Einstein. That is "Logic will get you from A to B. Imagination will take you everywhere."‘