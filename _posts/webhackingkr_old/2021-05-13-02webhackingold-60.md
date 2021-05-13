---
title: "[Webhacking.kr(old)]-60"
excerpt: webhacking.kr old 60번 문제 풀이
categories:
  - wargame
tags: [webhacking.kr_old, web]
toc: false

---

처음 페이지에 접속하면 아래와 같은 화면을 볼 수 있다.

![/assets/img/webkrold60%20c6aa31f9941a46edb9e8598aaec9d6fd/Untitled.png](/assets/img/webkrold60%20c6aa31f9941a46edb9e8598aaec9d6fd/Untitled.png)

view-source를 클릭하여 소스를 확인한다.

```php
<?php
  include "../../config.php";
  if($_GET['view_source']) view_source();
  login_chk();
  echo "Your idx is {$_SESSION['idx']}<hr>";
  if(!is_numeric($_COOKIE['PHPSESSID'])) exit("Access Denied<br><a href=./?view_source=1>view-source</a>");
  sleep(1);
  if($_GET['mode']=="auth"){
    echo("Auth~<br>");
    $result = file_get_contents("./readme/{$_SESSION['idx']}.txt");
    if(preg_match("/{$_SESSION['idx']}/",$result)){
      echo("Done!");
      unlink("./readme/{$_SESSION['idx']}.txt");
      solve(60);
      exit();
    }
  }
  $p = fopen("./readme/{$_SESSION['idx']}.txt","w");
  fwrite($p,$_SESSION['idx']);
  fclose($p);
  if($_SERVER['REMOTE_ADDR']!="127.0.0.1"){
    sleep(1);
    unlink("./readme/{$_SESSION['idx']}.txt");
  }
?>
<html><head><title>Challenge 60</title></head><body><a href=./?view_source=1>view-source</a></body></html>
```

아래 쪽 if문을 살펴보면 `REMOTE_ADDR` 의 값이 `127.0.0.1` 이 아닐경우 `sleep(1)` 함수를 실행시킨 후 unlink하는 부분이 존재한다.

```php
if($_SERVER['REMOTE_ADDR']!="127.0.0.1"){
    sleep(1);
    unlink("./readme/{$_SESSION['idx']}.txt");
  }
```

`?mode=auth` 로 접속하게 되면 /readme/[idx].txt 의 값을 읽어올 수 있다.

하지만 PHPSSID의 값이 숫자가 아닐 경우 AccessDenied가 반환되므로 값을 숫자로 바꿔준 후 새로운 세션을 하나 더 만들어주고 두개의 세션 모두 로그인을 해준다.

이후 `/` 경로에 한번 접속한 후 다른세션으로 빠르게 `/?mode=auth` 로 접속하면

![/assets/img/webkrold60%20c6aa31f9941a46edb9e8598aaec9d6fd/Untitled%201.png](/assets/img/webkrold60%20c6aa31f9941a46edb9e8598aaec9d6fd/Untitled%201.png)

문제를 풀이할 수 있다.