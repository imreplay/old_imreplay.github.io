---
title: "[Webhacking.kr(old)]-61"
excerpt: webhacking.kr old 61번 문제 풀이
categories:
  - wargame
tags: [webhacking.kr_old, web]
toc: false

---

view-source를 통해 문제 소스코드를 확인할 수 있다.
```php
<?php
  include "../../config.php";
  if($_GET['view_source']) view_source();
  $db = dbconnect();
  if(!$_GET['id']) $_GET['id']="guest";
  echo "<html><head><title>Challenge 61</title></head><body>";
  echo "<a href=./?view_source=1>view-source</a><hr>";
  $_GET['id'] = addslashes($_GET['id']);
  if(preg_match("/\(|\)|select|from|,|by|\./i",$_GET['id'])) exit("Access Denied");
  if(strlen($_GET['id'])>15) exit("Access Denied");
  $result = mysqli_fetch_array(mysqli_query($db,"select {$_GET['id']} from chall61 order by id desc limit 1"));
  echo "<b>{$result['id']}</b><br>";
  if($result['id'] == "admin") solve(61);
  echo "</body></html>";
?>
```

`select "admin" id from ~~~~` 와 같이 넣고 싶었지만, `addslashes` 때문에 `'` 문자나 `"` 문자를 사용하지 못한다. 

하지만, `0x61626364` == `abcd` 와 같이 사용할 수 있다.

![/assets/img/webkrold_61%201f7e6350973643f9a83e63b8792f4ebb/Untitled.png](/assets/img/webkrold_61%201f7e6350973643f9a83e63b8792f4ebb/Untitled.png)

`id=0x61646d696e%20id` 와 같이 설정해주면 풀이 끝!

![/assets/img/webkrold_61%201f7e6350973643f9a83e63b8792f4ebb/Untitled%201.png](/assets/img/webkrold_61%201f7e6350973643f9a83e63b8792f4ebb/Untitled%201.png)