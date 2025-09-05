from random import randint
from functools import lru_cache
from time import monotonic, perf_counter
import matplotlib.pyplot as plt


# Функция для генерации двоичного числа заданной битовой длины
def generator(l):
    p = [randint(0, 1) for _ in range(l)]
    p[0], p[-1] = 1, 1
    strr = "".join(map(str, p))
    p = int(strr, 2)
    return p


# Функция, реализующая тест Миллера-Рабина для проверки числа на простоту
def miller_rabin_test(n, i=5):
    s, t = 0, n - 1
    while t % 2 == 0:
        s += 1  # считаем степени двойки
        t //= 2  # то что остается - нечетный остаток
    for _ in range(i):
        a = randint(2, n - 1)
        x = pow(a, t, n)
        if x == 1 or x == n - 1:
            continue  # если это условие прошло, то второе не обрабатываем
        for _ in range(s):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:  # если без break, значит число составное
            return False
    return True


# Расширенный алгоритм Евклида
def ext_alg_Evklida(m, p):
    a, b = m, p
    u1, v1 = 1, 0
    u2, v2 = 0, 1
    while b != 0:
        q = a // b
        r = a % b
        a = b
        b = r
        r = u2
        u2 = u1 - q * u2
        u1 = r
        r = v2
        v2 = v1 - q * v2
        v1 = r
    if u1 < 0:
        u1 += p
    return u1


# Алгоритм Евклида
def alg_Evklida(a, b):
    while b != 0:
        t = a % b
        a = b
        b = t
    return a


# Функция для генерации публичного и приватного ключей
def get_keys(L, public, private):
    p = generator(L // 2)
    q = generator(L - (L // 2))
    while not miller_rabin_test(p):
        p = generator(L // 2)
    while not miller_rabin_test(q) or len(format(p * q, "b")) != L:
        q = generator(L - (L // 2))
    n = p * q

    func_euler = (p - 1) * (q - 1)
    e = int(input("Введите число е (3/17/257/65537): "))
    while alg_Evklida(func_euler, e) != 1:
        print("Choose another e")
        e = int(input("Введите число е (3/17/257/65537): "))
    d = ext_alg_Evklida(e, func_euler)

    with open(public, "w", encoding="utf-8") as publ:
        publ.write(str(e) + "\n" + str(n))
    with open(private, "w", encoding="utf-8") as priv:
        priv.write(str(d) + "\n" + str(n))


# Функция быстрого возведения в степень
def fast_pow_mod(x, d, n):
    y = 1
    while d > 0:
        if d % 2 != 0:
            y = (y * x) % n
        d = d // 2
        x = (x * x) % n
    return y


# Функция для шифрования текста
def encryption(filename, public, L):
    with open(public, "r", encoding="utf-8") as keys:
        e, n = keys.read().split("\n")

    bin_text = ""
    with open(filename, "r", encoding="utf-8") as txt:
        for el in txt.read():
            binchar = format(ord(el), "b")
            bin_text += "0" * (16 - len(binchar)) + binchar

    print(f"length of text: {len(bin_text)}")
    k = L // 4
    while k % 16 != 0:
        k -= 1
    encrypted_flow = ""
    for i in range(0, len(bin_text), k):
        Mi = int(bin_text[i : i + k], 2)
        ci_decimal = fast_pow_mod(Mi, int(e), int(n))
        ci_bin = format(ci_decimal, "b")  # str
        if len(ci_bin) < L:
            k_added = L - len(ci_bin)
            ci_bin = "0" * k_added + ci_bin
        encrypted_flow += ci_bin

    with open("encrypted.txt", "w", encoding="utf-8") as enc:
        enc.write(encrypted_flow)


# Функция для дешифрования текста
def decrypt(filename, private):
    with open(private, "r", encoding="utf-8") as keys:
        d, n = keys.read().split("\n")
    with open(filename, "r", encoding="utf-8") as enc:
        encrypted = enc.read()
    # print(f'length of ecnrypted: {len(encrypted)}')
    decr = ""
    l = len(format(int(n), "b"))
    k = l // 4
    while k % 16 != 0:
        k -= 1
    for i in range(0, len(encrypted), l):
        ci = int(encrypted[i : i + l], 2)
        mi = fast_pow_mod(ci, int(d), int(n))
        mi_bin = format(mi, "b")

        if len(mi_bin) < k:
            k_added = k - len(mi_bin)
            mi_bin = "0" * k_added + mi_bin

        for j in range(0, len(mi_bin), 16):
            decr += chr(int(mi_bin[j : j + 16], 2))

    with open("decrypted.txt", "w", encoding="utf-8") as out:
        out.write(decr)


# Вспомогательная рекурсивная функция для алгоритма Полларда
@lru_cache(maxsize=None)
def posled(ind, n):
    if ind == 1:
        return (2**2 + 1) % n
    else:
        return (posled(ind - 1, n) ** 2 + 1) % n


# Функция для атаки на алгоритм. Основа - ро-эвристика Полларда.
def Pollard_attack(n):
    k = 1
    nod = 0
    for _ in range(n):
        j = 2**k
        xj = posled(j - 1, n)
        for i in range(2**k + 1, 2 ** (k + 1) + 1):
            xi = posled(i - 1, n)
            nod = alg_Evklida(n, abs(xj - xi))
            if nod > 1:
                print(f"p: {nod}, q: {n//nod}")
                return nod
        k += 1


# Функция для вычисления закрытого ключа по открытому ключу на основе алгоритма Полларда
def attacking(public):
    with open(public, "r", encoding="utf-8") as keys:
        e, n = keys.read().split("\n")
    n = int(n)
    st = monotonic()
    Pollard_attack(n)
    end = monotonic()
    print(f"Time: {end-st}")


# Функция для построения графиков
def graphicks():
    # for 6
    # x = (0.25,0.275,0.3,0.325,0.35,0.375,0.4,0.425,0.45,0.475,0.5)
    # y = (0,0.062,0.344,0.391,0.359,1.188,2.657,7.969,35.58,36.625,36.669)
    # plt.xticks(x)
    # plt.plot(x, y, marker='o', linestyle='-', color='g')
    # plt.xlabel('Коэффициент r') #Подпись для оси х
    # plt.ylabel('Время факторизации t, с') #Подпись для оси y

    # for 5
    # x=(70,72, 74,76, 78,80,82,84,86,88,90,92)
    # y=(1.7562, 2.534, 3.876, 5.3532,7.591 ,9.747,16.3654,37.1218,34.5576,76.3152, 98.4532, 148.057)
    # plt.xticks(x)
    # plt.xlabel('Длина ключа L, бит') #Подпись для оси х
    # plt.ylabel('Время факторизации t, с') #Подпись для оси y
    # plt.plot(x, y, marker='o', linestyle='-', color='g')

    # for 7
    # v=(1616,4096,9920,13968,17488,19184,22386,25024,29216)
    # y1=(0.0050, 0.0050, 0.0087,0.0085,0.009,0.0092,0.0099, 0.0106, 0.0114)
    # y2=(0.0029, 0.0018, 0.0030,0.0039,0.004,0.0039,0.0044, 0.0050, 0.0054)
    # y3=(0.0015, 0.0019, 0.0028,0.0032,0.004,0.0040,0.0044, 0.0051, 0.0059)

    # # y1=(0.0160, 0.023, 0.054, 0.064, 0.086, 0.0916, 0.099, 0.122, 0.134)
    # # y2=(0.0289, 0.047, 0.113, 0.139, 0.175, 0.1879, 0.223, 0.247, 0.282)
    # # y3=(0.0551, 0.117, 0.257, 0.360, 0.447, 0.4718, 0.544, 0.656, 0.740)
    # plt.plot(v, y1, marker='o', linestyle='-', color='g', label='256')
    # plt.plot(v, y2, marker='o', linestyle='-', color='b', label='512')
    # plt.plot(v, y3, marker='o', linestyle='-', color='r', label='1024')
    # plt.xlabel('Длина исходного текста V, бит') #Подпись для оси х
    # plt.ylabel('Время шифрования t, с') #Подпись для оси y

    # for 8
    # v = (1616, 4096, 9920, 13968, 15216, 19184, 22386, 29216, 35472)
    # y1 = (6656 / v[0],16384 / v[1],39680 / v[2],56064 / v[3],60928 / v[4],76800 / v[5],89600 / v[6],116992 / v[7],142080 / v[8],)
    # y2 = (
    #     6656 / v[0],
    #     16384 / v[1],
    #     39936 / v[2],
    #     56320 / v[3],
    #     60928 / v[4],
    #     76800 / v[5],
    #     89600 / v[6],
    #     117248 / v[7],
    #     142336 / v[8],
    # )
    # y3 = (
    #     7168 / v[0],
    #     16384 / v[1],
    #     39936 / v[2],
    #     56320 / v[3],
    #     61440 / v[4],
    #     76800 / v[5],
    #     90122 / v[6],
    #     117760 / v[7],
    #     142336 / v[8],
    # )
    # plt.plot(v, y1, marker="o", linestyle="-", color="g", label="256")
    # plt.plot(v, y2, marker="o", linestyle="-", color="b", label="512")
    # plt.plot(v, y3, marker="o", linestyle="-", color="r", label="1024")
    # plt.xlabel("Длина исходного текста V, бит")  # Подпись для оси х
    # plt.ylabel("Коэффициент разрастания шифрограммы k")  # Подпись для оси y
    plt.legend()
    plt.grid(True)
    plt.show()


def main():
    L = int(input("Введите длину ключа L: "))
    public = "public.txt"
    private = "private.txt"

    get_keys(L, public, private)
    text = "text.txt"

    # st = perf_counter()
    encryption(text, public, L)
    # end = perf_counter()
    # print(f"Time for encryption: {end-st}")
    # graphicks()
    attacking(public)

    # st = perf_counter()
    decrypt("encrypted.txt", private)
    # end = perf_counter()
    # print(f"Time for decryption: {end-st}")


if __name__ == "__main__":
    main()
