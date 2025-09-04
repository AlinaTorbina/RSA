# RSA
В программе реализована процедура генерации открытого и закрытого ключей заданной длины. Открытый ключ в виде пары числе (e,n) записывается в файл public.txt, закрытый ключ в виде пары чисел 
(d,n) записывается в файл private.txt. 

Также написаны процедуры шифрования и дешифрования согласно алгоритму RSA. Открытый и закрытый ключи считываются из файлов public.txt и private.txt. 

Написана функция для атаки на алгоритм RSA (вычисление закрытого ключа по известному открытому ключу) с использованием ρ-эвристики Полларда. Результатом работы программы является разложение заданного числа n на два простых множителя p и q для любого считанного из файла public.txt числа n.

Также исследованы зависимости длительности шифрования и дешифрования от битовой длины сообщения при разных длинах ключа. Для отображения результатов написана функция построение графиков. 

Пример работы программы:

<img width="548" height="80" alt="image" src="https://github.com/user-attachments/assets/a3b505b8-73f4-4241-b845-8f291433ca2c" />

<img width="681" height="250" alt="image" src="https://github.com/user-attachments/assets/888f8739-1928-4902-9250-ccadbdff1e3c" />

<img width="667" height="256" alt="image" src="https://github.com/user-attachments/assets/a1f09400-f884-4cf4-a825-ff4d76dd47b1" />

<img width="930" height="310" alt="image" src="https://github.com/user-attachments/assets/b0267169-7f04-4158-ac54-e60a6b972d72" />

<img width="933" height="496" alt="image" src="https://github.com/user-attachments/assets/c3d46c3c-437c-456e-b9d9-a312faa58256" />

<img width="531" height="173" alt="image" src="https://github.com/user-attachments/assets/42ba4205-7960-43b9-b41a-09ca579467ef" />

<img width="804" height="582" alt="image" src="https://github.com/user-attachments/assets/59c226ce-d0bf-49e2-9e0c-13211411ae9d" />

<img width="739" height="550" alt="image" src="https://github.com/user-attachments/assets/0fcf579f-5cd0-4bc7-b253-db969c7c29c8" />




